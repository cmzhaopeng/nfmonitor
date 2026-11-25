//go:build !desktop

package main

import (
	"fmt"
	"os"
)

// 不带 desktop 标签构建的是无界面版本（服务器 / Docker 用）：没有桌面窗口，只有 serve / server 等子命令。
func runDesktop() {
	fmt.Fprintln(os.Stderr, "这个 nfmonitor 构建没有桌面窗口。\n  网页版（本机）: nfmonitor serve\n  服务器版（多主机、需登录）: nfmonitor server -h")
	os.Exit(2)
}
