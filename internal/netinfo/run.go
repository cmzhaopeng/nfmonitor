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
	cmd.Env = cEnv()
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

// cEnv 返回去掉所有语言设置、强制 C 语言环境的环境变量，保证工具输出是英文、格式稳定。
// 光设 LC_ALL=C 不够：Python 写的工具（如 ufw）用 gettext 时优先看 LANGUAGE，
// 不遵守 GNU 的"C 语言环境下忽略 LANGUAGE"规则，pkexec 也会把 LANGUAGE 透传给 helper。
func cEnv() []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LANG=") || strings.HasPrefix(kv, "LANGUAGE=") || strings.HasPrefix(kv, "LC_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "LC_ALL=C", "LANG=C", "LANGUAGE=C")
}

func run(name string, args ...string) (string, error) {
	return Run(8*time.Second, name, args...)
}
