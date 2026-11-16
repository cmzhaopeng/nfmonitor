// Package priv 负责拿到 root 才能读的数据。
//
// GUI 始终以普通用户运行；需要时用 pkexec 拉起同一个二进制的 `helper` 子命令。
// helper 通过 stdin/stdout 收发按行分隔的 JSON，只接受 netinfo.PrivCommands
// 里的命令名（全部只读、参数固定），stdin 关闭即退出。
package priv

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"nfmonitor/internal/netinfo"
)

type request struct {
	Cmd string `json:"cmd"`
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
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		var req request
		var resp response
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			resp.Err = "bad request"
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
