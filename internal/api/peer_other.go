//go:build !linux

package api

import "errors"

// 非 Linux 平台查不到回环连接的属主：serve 模式只在 Linux 上提供（Windows 用桌面窗口或 server 模式）。
func peerUID(string) (int, error) { return 0, errors.New("此平台不支持按用户校验回环连接") }
