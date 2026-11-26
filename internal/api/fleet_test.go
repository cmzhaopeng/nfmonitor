package api

import (
	"strconv"
	"strings"
	"testing"

	"nfmonitor/internal/netinfo"
)

func TestSummarizeSockets(t *testing.T) {
	n := &FleetNet{}
	summarizeSockets(n, []netinfo.Socket{
		{Proto: "tcp", State: "LISTEN", Local: "0.0.0.0", LocalPort: "22", Peer: "0.0.0.0", PeerPort: "*", App: "sshd"},
		{Proto: "tcp", State: "LISTEN", Local: "[::]", LocalPort: "22", Peer: "[::]", PeerPort: "*", App: "sshd"},
		{Proto: "tcp", State: "LISTEN", Local: "127.0.0.1", LocalPort: "5432", Peer: "0.0.0.0", PeerPort: "*", App: "postgres"},
		{Proto: "tcp", State: "LISTEN", Local: "*", LocalPort: "6379", Peer: "*", PeerPort: "*", App: "redis-server"},
		{Proto: "udp", State: "UNCONN", Local: "0.0.0.0", LocalPort: "53", Peer: "0.0.0.0", PeerPort: "*", App: "dnsmasq"},
		{Proto: "tcp", State: "ESTAB", Local: "10.0.0.2", LocalPort: "22", Peer: "10.0.0.9", PeerPort: "51000"},
		{Proto: "tcp", State: "ESTAB", Local: "10.0.0.2", LocalPort: "22", Peer: "10.0.0.9", PeerPort: "51001"},
		{Proto: "tcp", State: "ESTAB", Local: "127.0.0.1", LocalPort: "5432", Peer: "127.0.0.1", PeerPort: "40000"},
	})
	if n.Estab != 3 || n.Listens != 5 {
		t.Fatalf("counts: %+v", n)
	}
	var ports []string
	for _, e := range n.Exposed {
		ports = append(ports, e.Proto+"/"+e.Addr+"/"+itoa(e.Port))
	}
	if got := strings.Join(ports, " "); got != "tcp/*/22 udp/*/53 tcp/*/6379" {
		t.Fatalf("exposed: %s", got)
	}
	if len(n.TopPeers) != 1 || n.TopPeers[0].Peer != "10.0.0.9" || n.TopPeers[0].Conns != 2 {
		t.Fatalf("peers: %+v", n.TopPeers)
	}
	f := findings("root", &FleetFw{Privileged: true, Ufw: "inactive"}, n)
	var text []string
	for _, x := range f {
		text = append(text, x.Level+":"+x.Text)
	}
	all := strings.Join(text, "\n")
	if !strings.Contains(all, "crit:没有启用防火墙") || !strings.Contains(all, "6379（Redis）") || strings.Contains(all, "22（") {
		t.Fatalf("findings:\n%s", all)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestSummarizeFirewall(t *testing.T) {
	fw := netinfo.Firewall{Privileged: true, UfwStatus: "active", Ufw: &netinfo.UfwInfo{Status: "active", Defaults: map[string]string{"incoming": "allow"}},
		Tables: []netinfo.FwTable{{Backend: "nft", Chains: []netinfo.FwChain{
			{Name: "input", Base: true, Type: "filter", Hook: "input", Policy: "accept", Rules: []netinfo.FwRule{{Verdict: "jump", Target: "ufw-before-input"}}},
			{Name: "ufw-before-input", Rules: []netinfo.FwRule{{Verdict: "accept"}, {Verdict: "drop"}}},
		}}}}
	s := summarizeFirewall(fw)
	if s.Rules != 3 || s.InputPolicy != "accept" || !s.InputFiltering || s.Backend != "nft" || s.UfwIncoming != "allow" {
		t.Fatalf("summary: %+v", s)
	}
	f := findings("root", s, &FleetNet{})
	if len(f) != 1 || f[0].Level != "warn" || !strings.Contains(f[0].Text, "默认入站") {
		t.Fatalf("findings: %+v", f)
	}
	// 没拿到 root 数据时不下「没有防火墙」的结论
	if f := findings("none", &FleetFw{Ufw: "inactive"}, nil); len(f) != 1 || f[0].Level != "info" {
		t.Fatalf("no-root findings: %+v", f)
	}
}

func TestNoLocal(t *testing.T) {
	s, h := newTestServer(t)
	s.NoLocal = true
	h = s.Handler()
	if rec := call(h, "GET", "/api/links", "", false); rec.Code != 500 || !strings.Contains(rec.Body.String(), "这里不采集本机") {
		t.Fatalf("links: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/api/meta", "", false); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"local":false`) {
		t.Fatalf("meta: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/api/fleet", "", false); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hosts":[]`) {
		t.Fatalf("fleet: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/api/session", "", false); !strings.Contains(rec.Body.String(), `"local":false`) {
		t.Fatalf("session: %s", rec.Body)
	}
}
