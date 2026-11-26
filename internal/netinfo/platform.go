package netinfo

import (
	"errors"
	"runtime"
)

// LocalSupported 报告本机采集是否可用：采集层解析的是 Linux 工具（ip、ss、nft、/proc），
// 其他平台（Windows 客户端）只能作为管理端去监控远程 Linux 主机。
var LocalSupported = runtime.GOOS == "linux"

// ErrNoLocal 是在不支持本机采集的平台上请求本机数据时的错误。
var ErrNoLocal = errors.New("这里不采集本机：请在「主机管理」里添加或选择要监控的 Linux 主机")
