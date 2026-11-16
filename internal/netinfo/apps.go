package netinfo

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// AppIface 是某个应用在某块网卡上的流量。Via 非空表示这是发往本机另一个
// 程序（通常是代理）的回环连接。
type AppIface struct {
	Dev     string  `json:"dev"`
	Via     string  `json:"via"`
	Conns   int     `json:"conns"`
	RxRate  float64 `json:"rxRate"` // 字节/秒
	TxRate  float64 `json:"txRate"`
	RxTotal uint64  `json:"rxTotal"` // 自开始监测以来
	TxTotal uint64  `json:"txTotal"`
}

type AppProc struct {
	PID     int    `json:"pid"`
	User    string `json:"user"`
	Cmdline string `json:"cmdline"`
	Conns   int    `json:"conns"`
}

type App struct {
	Name    string     `json:"name"` // 空串 = 归属未知（其他用户的进程）
	Procs   []AppProc  `json:"procs"`
	Conns   int        `json:"conns"`   // 已建立的 TCP 连接
	Listens int        `json:"listens"` // 监听端口数
	UDP     int        `json:"udp"`     // UDP 套接字数（无流量计数）
	RxRate  float64    `json:"rxRate"`
	TxRate  float64    `json:"txRate"`
	RxTotal uint64     `json:"rxTotal"`
	TxTotal uint64     `json:"txTotal"`
	Ifaces  []AppIface `json:"ifaces"`
}

type AppsSnapshot struct {
	Since int64 `json:"since"` // 开始监测的时间（unix 毫秒）
	Time  int64 `json:"time"`
	Apps  []App `json:"apps"`
}

// EnrichSockets 给每个套接字补上所属应用名和所在网卡。
func EnrichSockets(socks []Socket) {
	devs := addrDevs()
	names := map[int]string{}
	for i := range socks {
		s := &socks[i]
		if s.Iface != "" {
			s.Dev = s.Iface
		} else {
			s.Dev = devs[strings.TrimPrefix(s.Local, "::ffff:")]
		}
		if s.PID == 0 {
			continue
		}
		n, ok := names[s.PID]
		if !ok {
			n = appName(s.PID, s.Process)
			names[s.PID] = n
		}
		s.App = n
	}
}

// addrDevs 返回 本机地址 → 网卡名。已连接套接字的本地地址就是它出口网卡的地址。
func addrDevs() map[string]string {
	m := map[string]string{}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				m[n.IP.String()] = ifc.Name
				if n.IP.IsLoopback() && n.IP.To4() != nil {
					m["127.0.0.53"], m["127.0.0.54"] = ifc.Name, ifc.Name
				}
			}
		}
	}
	return m
}

// appName 优先用可执行文件名（comm 会被截断到 15 个字符，线程还可能改名）。
func appName(pid int, comm string) string {
	if exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil {
		if b := filepath.Base(strings.TrimSuffix(exe, " (deleted)")); b != "" && b != "." && b != "/" {
			return b
		}
	}
	return comm
}

type flowKey struct{ app, dev, via string }

type flowAcc struct {
	rx, tx         uint64
	rxRate, txRate float64
	conns          int
}

// AppTracker 周期性采样套接字，把 TCP 字节计数的增量按「应用 × 网卡」累加。
// 只在有人查询时采样：超过 idleAfter 没有请求就停，下次请求再继续。
type AppTracker struct {
	Sample func() ([]Socket, error) // 返回已 Enrich 的套接字

	mu      sync.Mutex
	started bool
	lastReq time.Time
	since   time.Time
	prevT   time.Time
	prev    map[string][2]uint64 // 套接字 → {sent, recv}
	acc     map[flowKey]*flowAcc
	snap    AppsSnapshot
	err     error
}

const (
	sampleEvery = 2 * time.Second
	idleAfter   = 20 * time.Second
)

// Snapshot 返回最近一次采样的汇总；首次调用会启动后台采样。
func (t *AppTracker) Snapshot() (AppsSnapshot, error) {
	t.mu.Lock()
	t.lastReq = time.Now()
	if !t.started {
		t.started = true
		t.since = time.Now()
		t.acc = map[flowKey]*flowAcc{}
		t.mu.Unlock()
		t.sample()
		go func() {
			for range time.Tick(sampleEvery) {
				t.mu.Lock()
				idle := time.Since(t.lastReq) > idleAfter
				t.mu.Unlock()
				if !idle {
					t.sample()
				}
			}
		}()
		t.mu.Lock()
	}
	defer t.mu.Unlock()
	return t.snap, t.err
}

func sockKey(s Socket) string {
	return s.Proto + "|" + s.Local + ":" + s.LocalPort + "|" + s.Peer + ":" + s.PeerPort + "|" + strconv.Itoa(s.PID)
}

func (t *AppTracker) sample() {
	socks, err := t.Sample()
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.err = err
		return
	}
	t.err = nil
	first := t.prev == nil
	dt := now.Sub(t.prevT).Seconds()

	// 本机监听端口 → 应用名，用来识别"回环连到了谁"。
	listeners := map[string]string{}
	for _, s := range socks {
		if s.State == "LISTEN" && s.App != "" {
			listeners[s.LocalPort] = s.App
		}
	}
	for _, a := range t.acc {
		a.rxRate, a.txRate, a.conns = 0, 0, 0
	}
	type appAgg struct {
		procs        map[int]*AppProc
		listens, udp int
	}
	apps := map[string]*appAgg{}
	cur := make(map[string][2]uint64, len(socks))
	for _, s := range socks {
		ag := apps[s.App]
		if ag == nil {
			ag = &appAgg{procs: map[int]*AppProc{}}
			apps[s.App] = ag
		}
		if s.PID != 0 && ag.procs[s.PID] == nil {
			ag.procs[s.PID] = &AppProc{PID: s.PID}
		}
		switch {
		case s.Proto == "udp":
			ag.udp++
			continue
		case s.State == "LISTEN":
			ag.listens++
			continue
		}
		if p := ag.procs[s.PID]; p != nil {
			p.Conns++
		}
		k := flowKey{app: s.App, dev: s.Dev}
		if ip := net.ParseIP(s.Peer); ip != nil && ip.IsLoopback() {
			if via := listeners[s.PeerPort]; via != "" && via != s.App {
				k.via = via
			}
		}
		a := t.acc[k]
		if a == nil {
			a = &flowAcc{}
			t.acc[k] = a
		}
		a.conns++
		sk := sockKey(s)
		cur[sk] = [2]uint64{s.BytesSent, s.BytesRecv}
		if first {
			continue // 第一次采样只做基线
		}
		var dtx, drx uint64
		if p, ok := t.prev[sk]; !ok {
			dtx, drx = s.BytesSent, s.BytesRecv // 上次采样之后才建立的连接
		} else if s.BytesSent >= p[0] && s.BytesRecv >= p[1] {
			dtx, drx = s.BytesSent-p[0], s.BytesRecv-p[1]
		}
		a.tx += dtx
		a.rx += drx
		if dt > 0 {
			a.txRate += float64(dtx) / dt
			a.rxRate += float64(drx) / dt
		}
	}
	t.prev, t.prevT = cur, now

	byApp := map[string]*App{}
	get := func(name string) *App {
		a := byApp[name]
		if a == nil {
			a = &App{Name: name, Procs: []AppProc{}, Ifaces: []AppIface{}}
			byApp[name] = a
		}
		return a
	}
	for name, ag := range apps {
		a := get(name)
		a.Listens, a.UDP = ag.listens, ag.udp
		for _, p := range ag.procs {
			p.User, p.Cmdline = procUserCmd(p.PID)
			a.Procs = append(a.Procs, *p)
		}
		sort.Slice(a.Procs, func(i, j int) bool { return a.Procs[i].PID < a.Procs[j].PID })
	}
	for k, f := range t.acc {
		if f.conns == 0 && f.rx == 0 && f.tx == 0 {
			continue
		}
		a := get(k.app)
		a.Ifaces = append(a.Ifaces, AppIface{Dev: k.dev, Via: k.via, Conns: f.conns, RxRate: f.rxRate, TxRate: f.txRate, RxTotal: f.rx, TxTotal: f.tx})
		a.Conns += f.conns
		a.RxRate += f.rxRate
		a.TxRate += f.txRate
		a.RxTotal += f.rx
		a.TxTotal += f.tx
	}
	out := make([]App, 0, len(byApp))
	for _, a := range byApp {
		sort.Slice(a.Ifaces, func(i, j int) bool {
			x, y := a.Ifaces[i], a.Ifaces[j]
			if x.RxTotal+x.TxTotal != y.RxTotal+y.TxTotal {
				return x.RxTotal+x.TxTotal > y.RxTotal+y.TxTotal
			}
			return x.Dev+x.Via < y.Dev+y.Via
		})
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	t.snap = AppsSnapshot{Since: t.since.UnixMilli(), Time: now.UnixMilli(), Apps: out}
}

func procUserCmd(pid int) (usr, cmd string) {
	d := filepath.Join("/proc", strconv.Itoa(pid))
	if b, err := os.ReadFile(filepath.Join(d, "cmdline")); err == nil {
		cmd = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		if len(cmd) > 300 {
			cmd = cmd[:300] + "…"
		}
	}
	if st, err := os.Stat(d); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			usr = strconv.Itoa(int(sys.Uid))
			if u, err := user.LookupId(usr); err == nil {
				usr = u.Username
			}
		}
	}
	return
}
