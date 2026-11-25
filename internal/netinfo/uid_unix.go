//go:build unix

package netinfo

import (
	"os"
	"syscall"
)

// fileUID 返回文件属主的 uid（本机读 /proc/<pid> 时用来得到进程的用户）。
func fileUID(st os.FileInfo) (int, bool) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid), true
	}
	return 0, false
}
