package netinfo

import "testing"

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"ss":            "ss",
		"/usr/bin/ip":   "/usr/bin/ip",
		"":              "''",
		"a b":           "'a b'",
		"it's":          `'it'\''s'`,
		"$(id)":         "'$(id)'",
		"x;rm -rf /":    "'x;rm -rf /'",
		"--zone=public": "--zone=public",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParsePs(t *testing.T) {
	out := `    1 root     systemd         /sbin/init splash
  812 www-data nginx           nginx: worker process
 4321 alice    python3         /usr/bin/python3 -m http.server 8000
bad line
`
	m := parsePs(out)
	if len(m) != 3 {
		t.Fatalf("got %d entries: %+v", len(m), m)
	}
	if e := m[4321]; e.user != "alice" || e.comm != "python3" || e.exe != "python3" || e.cmdline != "/usr/bin/python3 -m http.server 8000" {
		t.Errorf("4321: %+v", e)
	}
	if e := m[812]; e.exe != "" || e.cmdline != "nginx: worker process" {
		t.Errorf("812: %+v", e)
	}
}

func TestParseIfaceSys(t *testing.T) {
	m := parseIfaceSys("eth0\t0\t1\t1000\te1000e\nwlan0\t1\t1\t\tiwlwifi\nlo\t0\t0\t\t\n")
	if x := m["eth0"]; !x.device || x.wireless || x.speed != 1000 || x.driver != "e1000e" {
		t.Errorf("eth0: %+v", x)
	}
	if x := m["wlan0"]; !x.wireless || x.speed != 0 {
		t.Errorf("wlan0: %+v", x)
	}
	if x, ok := m["lo"]; !ok || x.device {
		t.Errorf("lo: %+v", x)
	}
}
