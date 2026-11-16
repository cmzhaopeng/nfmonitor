// Package netinfo 采集本机网络状态：网卡、路由、策略路由、套接字、代理、防火墙。
// 所有采集都是只读的。
package netinfo

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// pkexec 会重置 PATH，所以工具一律在固定目录里找。
var toolDirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// ToolPath 返回工具的绝对路径，找不到返回空串。
func ToolPath(name string) string {
	for _, d := range toolDirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// Run 执行外部命令并返回 stdout；失败时错误里带上 stderr。
func Run(timeout time.Duration, name string, args ...string) (string, error) {
	p := ToolPath(name)
	if p == "" {
		return "", fmt.Errorf("%s: 未安装", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), fmt.Errorf("%s: %s", name, msg)
	}
	return out.String(), nil
}

func run(name string, args ...string) (string, error) {
	return Run(8*time.Second, name, args...)
}
