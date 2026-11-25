//go:build !unix

package netinfo

import "os"

// 非 Unix 平台（Windows）没有 uid；本机采集在这些平台上本来就不可用（见 LocalSupported）。
func fileUID(os.FileInfo) (int, bool) { return 0, false }
