package netinfo

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Sys 是被采集的那台机器：本机（Local），或经 SSH 连接的远程主机（见 internal/remote）。
// 采集层只通过它执行命令、读文件，解析逻辑两边共用。
type Sys interface {
	// Remote 为真表示这是远程主机：本机专有的数据源（环境变量、gsettings、bpftrace 探针）不可用。
	Remote() bool
	// Run 以普通权限执行一个工具（不经 shell 解释参数），返回 stdout。
	Run(timeout time.Duration, name string, args ...string) (string, error)
	// ReadFile 以普通权限读一个文件。
	ReadFile(path string) ([]byte, error)
	// HasTool 报告工具是否安装。
	HasTool(name string) bool
}

// RootSys 能以 root 身份执行命令：本机是已经以 root 运行的 helper，远程主机是 root 登录或 sudo。
type RootSys interface {
	Sys
	RunRoot(timeout time.Duration, name string, args ...string) (string, error)
	ReadFileRoot(path string) ([]byte, error)
}

type localSys struct{}

// Local 是本机。
var Local Sys = localSys{}

func (localSys) Remote() bool { return false }
func (localSys) Run(timeout time.Duration, name string, args ...string) (string, error) {
	return Run(timeout, name, args...)
}
func (localSys) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (localSys) HasTool(name string) bool             { return ToolPath(name) != "" }

// localRoot 是已经以 root 运行的本机（helper、ufw-apply 子进程里用）。
type localRoot struct{ localSys }

func (localRoot) RunRoot(timeout time.Duration, name string, args ...string) (string, error) {
	return Run(timeout, name, args...)
}
func (localRoot) ReadFileRoot(path string) ([]byte, error) { return os.ReadFile(path) }

func orLocal(s Sys) Sys {
	if s == nil {
		return Local
	}
	return s
}

// ShellQuote 把一个参数包成 POSIX shell 的单引号字符串（远程执行时拼命令行用）。
func ShellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ToolDirs 是查找工具的目录（远程执行时拼进 PATH）。
func ToolDirs() []string { return append([]string(nil), toolDirs...) }

// ---- 网卡的 sysfs 信息 ----

type ifaceSys struct {
	wireless, device bool
	speed            int
	driver           string
}

// 远程一次取回所有网卡的 sysfs 信息，免得每块网卡、每个文件都走一趟 SSH。
const ifaceSysScript = `for i in /sys/class/net/*; do n=${i##*/}; w=0; d=0; [ -e "$i/wireless" ] && w=1; [ -e "$i/device" ] && d=1; s=$(cat "$i/speed" 2>/dev/null); dr=$(readlink "$i/device/driver" 2>/dev/null); printf '%s\t%s\t%s\t%s\t%s\n' "$n" "$w" "$d" "$s" "${dr##*/}"; done`

func readIfaceSys(sys Sys) map[string]ifaceSys {
	m := map[string]ifaceSys{}
	if !sys.Remote() {
		dirs, _ := filepath.Glob("/sys/class/net/*")
		for _, d := range dirs {
			var x ifaceSys
			_, err := os.Stat(filepath.Join(d, "wireless"))
			x.wireless = err == nil
			_, err = os.Stat(filepath.Join(d, "device"))
			x.device = err == nil
			if b, err := os.ReadFile(filepath.Join(d, "speed")); err == nil {
				x.speed, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			}
			if t, err := os.Readlink(filepath.Join(d, "device/driver")); err == nil {
				x.driver = filepath.Base(t)
			}
			m[filepath.Base(d)] = x
		}
		return m
	}
	out, err := sys.Run(8*time.Second, "sh", "-c", ifaceSysScript)
	if err != nil {
		return m
	}
	return parseIfaceSys(out)
}

func parseIfaceSys(out string) map[string]ifaceSys {
	m := map[string]ifaceSys{}
	for _, l := range strings.Split(out, "\n") {
		fs := strings.Split(l, "\t")
		if len(fs) < 5 || fs[0] == "" {
			continue
		}
		x := ifaceSys{wireless: fs[1] == "1", device: fs[2] == "1", driver: fs[4]}
		x.speed, _ = strconv.Atoi(strings.TrimSpace(fs[3]))
		m[fs[0]] = x
	}
	return m
}

// ---- 进程信息 ----

type procEntry struct {
	user, comm, cmdline, exe string
}

// procTable 是一次进程快照：本机按需读 /proc，远程主机一次 ps 取回全部。
type procTable struct {
	sys     Sys
	mu      sync.Mutex
	remote  map[int]procEntry
	fetched bool
}

func newProcTable(sys Sys) *procTable { return &procTable{sys: orLocal(sys)} }

// 远程用 ps：comm 会截断到 15 个字符，所以可执行文件名从 args 的第一个词取。
const psScript = `ps -ww -e -o pid= -o user:64= -o comm= -o args= 2>/dev/null || ps -ww -e -o pid= -o user= -o comm= -o args=`

func (t *procTable) load() {
	if t.fetched {
		return
	}
	t.fetched = true
	t.remote = map[int]procEntry{}
	out, err := t.sys.Run(8*time.Second, "sh", "-c", psScript)
	if err != nil {
		return
	}
	t.remote = parsePs(out)
}

func parsePs(out string) map[int]procEntry {
	m := map[int]procEntry{}
	for _, l := range strings.Split(out, "\n") {
		fs := strings.Fields(l)
		if len(fs) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fs[0])
		if err != nil {
			continue
		}
		e := procEntry{user: fs[1], comm: fs[2]}
		if len(fs) > 3 {
			e.cmdline = strings.Join(fs[3:], " ")
			if first := fs[3]; strings.HasPrefix(first, "/") {
				e.exe = filepath.Base(first)
			}
		}
		m[pid] = e
	}
	return m
}

func (t *procTable) get(pid int) (procEntry, bool) {
	if !t.sys.Remote() {
		var e procEntry
		d := filepath.Join("/proc", strconv.Itoa(pid))
		st, err := os.Stat(d)
		if err != nil {
			return e, false
		}
		if b, err := os.ReadFile(filepath.Join(d, "comm")); err == nil {
			e.comm = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(filepath.Join(d, "cmdline")); err == nil {
			e.cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		}
		if exe, err := os.Readlink(filepath.Join(d, "exe")); err == nil {
			e.exe = filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			e.user = strconv.Itoa(int(sys.Uid))
			if u, err := user.LookupId(e.user); err == nil {
				e.user = u.Username
			}
		}
		return e, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.load()
	e, ok := t.remote[pid]
	return e, ok
}

// all 列出所有进程的 pid → comm（远程直接用 ps 的结果，本机扫 /proc）。
func (t *procTable) all() map[int]string {
	m := map[int]string{}
	if !t.sys.Remote() {
		dirs, _ := filepath.Glob("/proc/[0-9]*")
		for _, d := range dirs {
			b, err := os.ReadFile(filepath.Join(d, "comm"))
			if err != nil {
				continue
			}
			pid, _ := strconv.Atoi(filepath.Base(d))
			m[pid] = strings.TrimSpace(string(b))
		}
		return m
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.load()
	for pid, e := range t.remote {
		m[pid] = e.comm
	}
	return m
}
