package netinfo

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UDP 套接字在内核里没有逐套接字的字节计数（ss 看不到），只能在收发路径上挂探针。
// 这里用 bpftrace 挂三个 kprobe，按「进程 × 本地端口 × 网卡」汇总每秒的载荷字节数：
//   - udp_sendmsg / udpv6_sendmsg(sk, msg, len)：发送，len 是载荷长度
//   - skb_consume_udp(sk, skb, len)：接收，len 是拷给进程的字节数（MSG_PEEK 时为负，跳过）
//
// 探针只读内核数据，不改任何网络状态。需要 root，所以由提权 helper 运行。
const udpScript = `kprobe:udp_sendmsg,kprobe:udpv6_sendmsg {
  $sk = (struct sock *)arg0;
  @tx[pid, $sk->__sk_common.skc_num, $sk->__sk_common.skc_bound_dev_if, comm] = sum(arg2);
}
kprobe:skb_consume_udp /(int32)arg2 > 0/ {
  $sk = (struct sock *)arg0;
  $skb = (struct sk_buff *)arg1;
  @rx[pid, $sk->__sk_common.skc_num, $skb->skb_iif, comm] = sum((int32)arg2);
}
interval:s:1 {
  print(@tx); clear(@tx);
  print(@rx); clear(@rx);
  printf("T %llu\n", nsecs);
}`

// UDPFlow 是一段时间内某进程某个 UDP 端口的收发字节数（增量）。
type UDPFlow struct {
	PID     int
	Port    int
	Ifindex int    // 接收：包进来的网卡；发送：套接字绑定的网卡（多数为 0）
	Comm    string // 线程名，进程已退出时用它兜底
	Rx, Tx  uint64
}

// UDPStat 是一次取数的结果。T 是这批数据截止的内核时钟（纳秒），
// 相邻两次的 T 之差就是这批增量对应的时长；没有新数据时 T 为 0。
type UDPStat struct {
	T     uint64
	Flows []UDPFlow
}

var udpLine = regexp.MustCompile(`^@(rx|tx)\[(\d+), (\d+), (-?\d+), (.*)\]: (\d+)$`)

// ParseUDPStat 解析 bpftrace 的 map 输出（也是 helper 回传的格式）。
func ParseUDPStat(out string) UDPStat {
	var st UDPStat
	idx := map[string]int{}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if t, ok := strings.CutPrefix(ln, "T "); ok {
			if n, err := strconv.ParseUint(t, 10, 64); err == nil && n > st.T {
				st.T = n
			}
			continue
		}
		m := udpLine.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		key := m[2] + "," + m[3] + "," + m[4] + "," + m[5]
		i, ok := idx[key]
		if !ok {
			f := UDPFlow{Comm: m[5]}
			f.PID, _ = strconv.Atoi(m[2])
			f.Port, _ = strconv.Atoi(m[3])
			f.Ifindex, _ = strconv.Atoi(m[4])
			i = len(st.Flows)
			idx[key] = i
			st.Flows = append(st.Flows, f)
		}
		n, _ := strconv.ParseUint(m[6], 10, 64)
		if m[1] == "rx" {
			st.Flows[i].Rx += n
		} else {
			st.Flows[i].Tx += n
		}
	}
	return st
}

// udpMonitor 在 root 侧管理 bpftrace 子进程：第一次取数时启动，
// 超过 udpIdle 没人取数就停掉（探针随之卸载），下次取数再启动。
type udpMonitor struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	pending  map[string]uint64 // 当前这一秒还没收全的行
	ready    map[string]uint64 // 已收全、等待取走的增量
	readyT   uint64
	lastReq  time.Time
	err      error
	failedAt time.Time
}

const (
	udpIdle  = 30 * time.Second
	udpRetry = 30 * time.Second
)

var udpMon = &udpMonitor{}

// StopUDPMonitor 结束 bpftrace（helper 退出前调用）。
func StopUDPMonitor() {
	udpMon.mu.Lock()
	defer udpMon.mu.Unlock()
	if udpMon.cmd != nil {
		udpMon.cmd.Process.Kill()
		udpMon.cmd = nil
	}
}

// drain 取走上次调用以来的增量，文本格式与 bpftrace 输出一致。
func (m *udpMonitor) drain() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastReq = time.Now()
	if m.cmd == nil {
		if m.err != nil && time.Since(m.failedAt) < udpRetry {
			return "", m.err
		}
		if err := m.startLocked(); err != nil {
			m.err, m.failedAt = err, time.Now()
			return "", err
		}
	}
	keys := make([]string, 0, len(m.ready))
	for k := range m.ready {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %d\n", k, m.ready[k])
	}
	if m.readyT != 0 {
		fmt.Fprintf(&b, "T %d\n", m.readyT)
	}
	m.ready, m.readyT = map[string]uint64{}, 0
	return b.String(), nil
}

func (m *udpMonitor) startLocked() error {
	bin := ToolPath("bpftrace")
	if bin == "" {
		return errors.New("未安装 bpftrace，无法统计 UDP 流量（sudo apt install bpftrace）")
	}
	cmd := exec.Command(bin, "-q", "-e", udpScript)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	m.cmd, m.err = cmd, nil
	m.pending, m.ready, m.readyT = map[string]uint64{}, map[string]uint64{}, 0
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			ln := strings.TrimSpace(sc.Text())
			m.mu.Lock()
			if m.cmd != cmd {
				m.mu.Unlock()
				break
			}
			if t, ok := strings.CutPrefix(ln, "T "); ok {
				for k, v := range m.pending {
					m.ready[k] += v
				}
				m.pending = map[string]uint64{}
				m.readyT, _ = strconv.ParseUint(t, 10, 64)
				if time.Since(m.lastReq) > udpIdle {
					cmd.Process.Kill()
					m.cmd = nil
				}
			} else if i := strings.LastIndex(ln, "]: "); i > 0 && udpLine.MatchString(ln) {
				n, _ := strconv.ParseUint(ln[i+3:], 10, 64)
				m.pending[ln[:i+1]] += n
			}
			m.mu.Unlock()
		}
		cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd { // 不是我们主动停的：启动失败或中途退出
			m.cmd = nil
			msg := strings.TrimSpace(stderr.String())
			if len(msg) > 400 {
				msg = msg[:400] + "…"
			}
			if msg == "" {
				msg = "已退出"
			}
			m.err, m.failedAt = errors.New("bpftrace: "+msg), time.Now()
		}
		m.mu.Unlock()
	}()
	return nil
}
