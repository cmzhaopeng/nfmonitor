package priv

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"testing"

	"nfmonitor/internal/netinfo"
)

// 子进程模式：本测试二进制以 NFMONITOR_TEST_HELPER=1 运行时充当 helper。
func TestMain(m *testing.M) {
	if os.Getenv("NFMONITOR_TEST_HELPER") == "1" {
		ServeHelper(os.Stdin, os.Stdout)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func startHelper(t *testing.T) *Client {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "NFMONITOR_TEST_HELPER=1")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(stdout)
	if _, err := rd.ReadBytes('\n'); err != nil { // ready 握手
		t.Fatal(err)
	}
	c := &Client{cmd: cmd, stdin: stdin, rd: rd}
	t.Cleanup(c.Close)
	return c
}

func TestApplyViaHelper(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 运行会真的改 ufw")
	}
	c := startHelper(t)
	_, err, ok := c.applyViaHelper(netinfo.UfwOp{Op: "enable"})
	if !ok || err == nil || !strings.Contains(err.Error(), "需要 root") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	// 同一个 helper 之后仍能正常处理只读命令（协议没被打乱）。
	if _, err := c.Run("no-such-cmd"); err == nil || !strings.Contains(err.Error(), "不允许") {
		t.Fatalf("Run after apply: %v", err)
	}
	// 没有 helper 时 ok=false，调用方退回 pkexec。
	if _, _, ok := (&Client{}).applyViaHelper(netinfo.UfwOp{Op: "enable"}); ok {
		t.Fatal("expected ok=false without helper")
	}
}
