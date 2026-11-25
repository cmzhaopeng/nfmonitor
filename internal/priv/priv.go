// Package priv 负责拿到 root 才能读的数据。
//
// GUI 始终以普通用户运行；需要时用 pkexec 拉起同一个二进制的 `helper` 子命令。
// helper 通过 stdin/stdout 收发按行分隔的 JSON，只接受 netinfo.PrivCommands
// 里的命令名（全部只读、参数固定），stdin 关闭即退出。
package priv

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nfmonitor/internal/netinfo"
)

type request struct {
	Cmd string         `json:"cmd,omitempty"`
	Ufw *netinfo.UfwOp `json:"ufw,omitempty"` // 一次 ufw 修改：root 侧经 ApplyUfw 重新校验后执行
}

type response struct {
	Ready bool   `json:"ready,omitempty"`
	Out   string `json:"out"`
	Err   string `json:"err,omitempty"`
}

// ServeHelper 是 root 侧的主循环。
func ServeHelper(in io.Reader, out io.Writer) error {
	enc := json.NewEncoder(out)
	if err := enc.Encode(response{Ready: true}); err != nil {
		return err
	}
	defer netinfo.StopUDPMonitor()
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		var req request
		var resp response
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			resp.Err = "bad request"
		} else if req.Ufw != nil {
			res, err := netinfo.ApplyUfw(*req.Ufw)
			b, _ := json.Marshal(res)
			resp.Out = string(b)
			if err != nil {
				resp.Err = err.Error()
			}
		} else if o, err := netinfo.RunPrivCommand(req.Cmd); err != nil {
			resp.Out, resp.Err = o, err.Error()
		} else {
			resp.Out = o
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

// fixtureDir 仅供开发：设了 NFMONITOR_FIXTURE_DIR 就从 <dir>/<命令名>.txt 读"root 输出"，
// 不用真的提权也能调界面。
var fixtureDir = os.Getenv("NFMONITOR_FIXTURE_DIR")

// ErrNotElevated 表示还没有授权，需要用户点一下"授权"。
var ErrNotElevated = errors.New("需要 root 权限（尚未授权）")

// Client 是普通用户侧的句柄。
type Client struct {
	mu    sync.Mutex
	cmd   *exec.Cmd
	stdin io.WriteCloser
	rd    *bufio.Reader
}

func NewClient() *Client { return &Client{} }

// Status: root（本进程就是 root）| helper（已授权）| none。
func (c *Client) Status() string {
	if fixtureDir != "" {
		return "helper"
	}
	if os.Geteuid() == 0 {
		return "root"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		return "helper"
	}
	return "none"
}

// Elevate 通过 pkexec 启动 helper，会弹出系统的授权对话框。
func (c *Client) Elevate() error {
	if os.Geteuid() == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		return nil
	}
	pkexec := netinfo.ToolPath("pkexec")
	if pkexec == "" {
		return errors.New("未找到 pkexec（请安装 polkit，或用 sudo 运行本程序）")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(pkexec, self, "helper")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(stdout, 1<<20)
	ready := make(chan error, 1)
	go func() {
		line, err := rd.ReadBytes('\n')
		var r response
		if err == nil && (json.Unmarshal(line, &r) != nil || !r.Ready) {
			err = errors.New("helper 握手失败")
		}
		ready <- err
	}()
	select {
	case err = <-ready:
	case <-time.After(3 * time.Minute):
		err = errors.New("等待授权超时")
	}
	if err != nil {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("授权未完成: %w", err)
	}
	c.cmd, c.stdin, c.rd = cmd, stdin, rd
	return nil
}

// Run 执行一条白名单命令：本身是 root 就直接跑，否则走 helper。
func (c *Client) Run(name string) (string, error) {
	if fixtureDir != "" {
		if _, ok := netinfo.PrivCommands[name]; !ok {
			return "", fmt.Errorf("不允许的命令: %s", name)
		}
		b, err := os.ReadFile(filepath.Join(fixtureDir, name+".txt"))
		return string(b), err
	}
	if os.Geteuid() == 0 {
		return netinfo.RunPrivCommand(name)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd == nil {
		return "", ErrNotElevated
	}
	b, _ := json.Marshal(request{Cmd: name})
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		c.closeLocked()
		return "", ErrNotElevated
	}
	line, err := c.rd.ReadBytes('\n')
	if err != nil {
		c.closeLocked()
		return "", ErrNotElevated
	}
	var r response
	if err := json.Unmarshal(line, &r); err != nil {
		return "", err
	}
	if r.Err != "" {
		return r.Out, errors.New(r.Err)
	}
	return r.Out, nil
}

// ApplyUfw 执行一次 ufw 修改。写操作不走只读 helper：每次单独用
// `pkexec <self> ufw-apply` 起一个 root 进程，操作经 stdin 传入，由它重新校验后执行。
// 样例模式下只返回将要执行的命令，不执行。
func (c *Client) ApplyUfw(op netinfo.UfwOp) (netinfo.UfwResult, error) {
	if fixtureDir != "" {
		var cur []netinfo.UfwRule
		if out, err := c.Run("ufw-tuples"); err == nil {
			cur = netinfo.ParseUfwTuples(out, true)
		}
		cmds, err := netinfo.BuildUfw(op, cur, true)
		if err != nil {
			return netinfo.UfwResult{}, err
		}
		var out strings.Builder
		for _, c := range cmds {
			out.WriteString("$ " + strings.Join(c, " ") + "\n")
		}
		out.WriteString("（样例模式：以上命令未执行）")
		return netinfo.UfwResult{Commands: cmds, Output: out.String()}, nil
	}
	if os.Geteuid() == 0 {
		return netinfo.ApplyUfw(op)
	}
	// 已授权：交给常驻的 root helper，不再弹授权框。
	if res, err, ok := c.applyViaHelper(op); ok {
		return res, err
	}
	pkexec := netinfo.ToolPath("pkexec")
	if pkexec == "" {
		return netinfo.UfwResult{}, errors.New("未找到 pkexec（请安装 polkit，或用 sudo 运行本程序）")
	}
	self, err := os.Executable()
	if err != nil {
		return netinfo.UfwResult{}, err
	}
	in, _ := json.Marshal(op)
	cmd := exec.Command(pkexec, self, "ufw-apply")
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return netinfo.UfwResult{}, err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-time.After(3 * time.Minute):
		cmd.Process.Kill()
		<-done
		return netinfo.UfwResult{}, errors.New("等待授权超时")
	}
	var r ApplyReply
	if jerr := json.Unmarshal(stdout.Bytes(), &r); jerr != nil {
		// pkexec 自己失败（取消授权返回 126、未授权 127）时没有 JSON 输出。
		if ee, ok := err.(*exec.ExitError); ok && (ee.ExitCode() == 126 || ee.ExitCode() == 127) {
			return netinfo.UfwResult{}, errors.New("授权被取消，未做任何修改")
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" && err != nil {
			msg = err.Error()
		}
		return netinfo.UfwResult{}, fmt.Errorf("执行失败: %s", msg)
	}
	if r.Error != "" {
		return r.Result, errors.New(r.Error)
	}
	return r.Result, nil
}

// applyViaHelper 经已授权的 helper 执行；ok=false 表示 helper 没在运行。
func (c *Client) applyViaHelper(op netinfo.UfwOp) (res netinfo.UfwResult, err error, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd == nil {
		return res, nil, false
	}
	b, _ := json.Marshal(request{Ufw: &op})
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		c.closeLocked()
		return res, nil, false
	}
	line, err := c.rd.ReadBytes('\n')
	if err != nil {
		c.closeLocked()
		return res, ErrNotElevated, true
	}
	var r response
	if err := json.Unmarshal(line, &r); err != nil {
		return res, err, true
	}
	if jerr := json.Unmarshal([]byte(r.Out), &res); jerr != nil && r.Err == "" {
		return res, errors.New("助手返回了无法识别的结果（程序升级后请重启 nfmonitor）"), true
	}
	if r.Err != "" {
		if strings.HasPrefix(r.Err, "不允许的命令") {
			r.Err = "正在运行的 root 助手是旧版本，请重启 nfmonitor 后重试"
		}
		return res, errors.New(r.Err), true
	}
	return res, nil, true
}

// ApplyReply 是 ufw-apply 子命令写到 stdout 的结果。
type ApplyReply struct {
	Result netinfo.UfwResult `json:"result"`
	Error  string            `json:"error,omitempty"`
}

// ServeUfwApply 是 `nfmonitor ufw-apply` 的主体（root 侧）：从 stdin 读一个操作，执行，写回结果。
func ServeUfwApply(in io.Reader, out io.Writer) error {
	var op netinfo.UfwOp
	var reply ApplyReply
	if err := json.NewDecoder(io.LimitReader(in, 64<<10)).Decode(&op); err != nil {
		reply.Error = "bad request"
	} else if res, err := netinfo.ApplyUfw(op); err != nil {
		reply.Result, reply.Error = res, err.Error()
	} else {
		reply.Result = res
	}
	return json.NewEncoder(out).Encode(reply)
}

// Close 结束 helper。
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *Client) closeLocked() {
	if c.cmd == nil {
		return
	}
	c.stdin.Close()
	done := make(chan struct{})
	go func() { c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		c.cmd.Process.Kill()
	}
	c.cmd = nil
}
