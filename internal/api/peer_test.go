package api

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestProcHex(t *testing.T) {
	if got := procHex(netip.MustParseAddrPort("127.0.0.1:8787"), false); got != "0100007F:2253" {
		t.Errorf("v4 = %q", got)
	}
	if got := procHex(netip.MustParseAddrPort("[::1]:80"), true); got != "00000000000000000000000001000000:0050" {
		t.Errorf("v6 = %q", got)
	}
}

func TestPeerUID(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { c, _ := ln.Accept(); defer c.Close(); select {} }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := peerUID(c.LocalAddr().String()) // 服务端看到的 RemoteAddr 就是客户端的本地地址
	if err != nil || uid != os.Getuid() {
		t.Errorf("peerUID = %d, %v; want %d", uid, err, os.Getuid())
	}
}
