package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 审计日志：<数据目录>/audit.log，每行一条 JSON，只追加（0600）。
// 同时打到标准输出（systemd journal / docker logs），这样即使数据目录里的文件被改，另一份还在。
// 超过 auditMaxSize 时轮转成 audit.log.1 … audit.log.<auditKeep>。

const (
	auditMaxSize = 20 << 20
	auditKeep    = 5
)

// AuditEntry 是一条审计记录。不含任何口令 / 私钥。
type AuditEntry struct {
	Time     time.Time      `json:"time"`
	User     string         `json:"user,omitempty"`
	IP       string         `json:"ip,omitempty"`
	Action   string         `json:"action"`             // 例：login、hosts/save、ufw/apply
	Host     string         `json:"host,omitempty"`     // 目标主机 ID
	HostName string         `json:"hostName,omitempty"` // 目标主机名称（记录时的）
	Result   string         `json:"result"`             // ok | error | denied
	Error    string         `json:"error,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
}

type Audit struct {
	path   string
	mu     sync.Mutex
	f      *os.File
	size   int64
	stdout io.Writer
}

func OpenAudit(dir string) (*Audit, error) {
	a := &Audit{path: filepath.Join(dir, "audit.log"), stdout: os.Stdout}
	if err := a.open(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Audit) open() error {
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	a.f, a.size = f, st.Size()
	return nil
}

// Log 写一条记录。写文件失败时只打日志，不影响请求本身（但会在标准输出留下记录）。
func (a *Audit) Log(e AuditEntry) {
	if a == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stdout != nil {
		fmt.Fprintf(a.stdout, "audit %s", b)
	}
	if a.f == nil {
		return
	}
	if a.size+int64(len(b)) > auditMaxSize {
		a.rotate()
	}
	n, err := a.f.Write(b)
	a.size += int64(n)
	if err != nil {
		log.Printf("写审计日志失败: %v", err)
	}
}

func (a *Audit) rotate() {
	a.f.Close()
	a.f = nil
	for i := auditKeep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", a.path, i), fmt.Sprintf("%s.%d", a.path, i+1))
	}
	os.Rename(a.path, a.path+".1")
	if err := a.open(); err != nil {
		log.Printf("轮转审计日志失败: %v", err)
	}
}

// Recent 返回最近 limit 条记录（新的在前），只读当前文件的末尾一段。
func (a *Audit) Recent(limit int) ([]AuditEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.Open(a.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const tail = 4 << 20
	off := int64(0)
	if st.Size() > tail {
		off = st.Size() - tail
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, err
	}
	if off > 0 { // 丢掉第一行（可能不完整）
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	var all []AuditEntry
	sc := bufio.NewScanner(bytes.NewReader(buf))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	out := make([]AuditEntry, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

func (a *Audit) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		a.f.Close()
		a.f = nil
	}
}
