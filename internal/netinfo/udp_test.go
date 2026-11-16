package netinfo

import (
	"testing"
	"time"
)

func TestParseUDPStat(t *testing.T) {
	st := ParseUDPStat(`
@tx[1234, 443, 0, chrome]: 100
@tx[1234, 443, 0, chrome]: 50

@rx[1234, 443, 3, chrome]: 900
@rx[77, 53, 1, systemd-resolve]: 64
@tx[88, 5353, 0, a, b]c]: 7
T 5000
garbage
T 7000
`)
	if st.T != 7000 {
		t.Fatalf("T = %d", st.T)
	}
	if len(st.Flows) != 4 {
		t.Fatalf("flows = %+v", st.Flows)
	}
	want := []UDPFlow{
		{PID: 1234, Port: 443, Ifindex: 0, Comm: "chrome", Tx: 150},
		{PID: 1234, Port: 443, Ifindex: 3, Comm: "chrome", Rx: 900},
		{PID: 77, Port: 53, Ifindex: 1, Comm: "systemd-resolve", Rx: 64},
		{PID: 88, Port: 5353, Ifindex: 0, Comm: "a, b]c", Tx: 7},
	}
	for i, w := range want {
		if st.Flows[i] != w {
			t.Errorf("flow %d = %+v, want %+v", i, st.Flows[i], w)
		}
	}
}

func TestAddUDP(t *testing.T) {
	tr := &AppTracker{acc: map[flowKey]*flowAcc{}, defDev: "eth9"}
	tr.defDevAt = time.Now()
	socks := []Socket{{Proto: "udp", PID: 10, LocalPort: "443", App: "browser", Dev: "tun0"}}
	tr.addUDP(UDPStat{T: 1e9, Flows: []UDPFlow{{PID: 10, Port: 443, Tx: 100}, {PID: 10, Port: 999, Tx: 40}}}, socks, 2)
	tr.addUDP(UDPStat{T: 3e9, Flows: []UDPFlow{{PID: 10, Port: 443, Tx: 200, Rx: 600}}}, socks, 5)
	a := tr.acc[flowKey{app: "browser", dev: "tun0"}]
	if a == nil || a.tx != 300 || a.rx != 600 || a.udpTx != 300 || a.udpRx != 600 {
		t.Fatalf("tun0 acc = %+v", a)
	}
	if a.rxRate != 300 { // 第二批按探针时钟：600 / 2s
		t.Errorf("rxRate = %v", a.rxRate)
	}
	if b := tr.acc[flowKey{app: "browser", dev: "eth9"}]; b == nil || b.tx != 40 {
		t.Errorf("fallback dev acc = %+v", b)
	}
}
