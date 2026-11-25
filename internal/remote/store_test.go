package remote

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreEncryptsSecrets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := st.Put(HostConfig{Addr: "10.0.0.2", User: "ops", Auth: AuthPassword, Password: "s3cret-pw", SudoPassword: "sudo-pw"})
	if err != nil {
		t.Fatal(err)
	}
	if h.ID == "" || h.Port != 22 || h.Name != "ops@10.0.0.2" {
		t.Errorf("defaults not filled: %+v", h)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret-pw") || strings.Contains(string(raw), "sudo-pw") {
		t.Fatalf("plaintext secret on disk:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"password": "v1:`) {
		t.Errorf("password not stored encrypted:\n%s", raw)
	}
	for _, f := range []string{"hosts.json", "secret.key"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if p := st.Mode().Perm(); p != 0o600 {
			t.Errorf("%s mode %o, want 600", f, p)
		}
	}
	if d, _ := os.Stat(dir); d.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o, want 700", d.Mode().Perm())
	}

	// 重新打开能解密
	st2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := st2.Get(h.ID)
	if !ok || got.Password != "s3cret-pw" || got.SudoPassword != "sudo-pw" {
		t.Fatalf("round trip: %+v", got)
	}

	// 把密文挪到别的字段：附加数据不符，解密失败
	swapped := strings.Replace(string(raw), `"sudoPassword"`, `"passphrase"`, 1)
	os.WriteFile(filepath.Join(dir, "hosts.json"), []byte(swapped), 0o600)
	if _, err := OpenStore(dir); err == nil {
		t.Error("moved ciphertext should not decrypt")
	}
	os.WriteFile(filepath.Join(dir, "hosts.json"), raw, 0o644)

	// 换了 secret.key：解密失败
	os.WriteFile(filepath.Join(dir, "secret.key"), make([]byte, 32), 0o600)
	if _, err := OpenStore(dir); err == nil {
		t.Error("wrong key should not decrypt")
	}
	if st, _ := os.Stat(filepath.Join(dir, "hosts.json")); st.Mode().Perm() != 0o600 {
		t.Errorf("loose permissions not tightened: %o", st.Mode().Perm())
	}
}

func TestStoreDelete(t *testing.T) {
	st, _ := OpenStore(t.TempDir())
	a, _ := st.Put(HostConfig{Addr: "a.example", User: "u", Auth: AuthPassword, Password: "x"})
	b, _ := st.Put(HostConfig{Addr: "b.example", User: "u", Auth: AuthPassword, Password: "x"})
	if err := st.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if l := st.List(); len(l) != 1 || l[0].ID != b.ID {
		t.Errorf("after delete: %+v", l)
	}
	if err := st.Delete(a.ID); err == nil {
		t.Error("double delete should fail")
	}
}

func TestValidate(t *testing.T) {
	ok := []HostConfig{
		{Addr: "192.168.1.10", User: "root", Auth: AuthPassword, Password: "x"},
		{Addr: "[2001:db8::1]", Port: 2222, User: "ops", Auth: AuthPassword, Password: "x"},
		{Addr: "web-01.example.com", User: "deploy", Auth: AuthKey, KeyPath: "/tmp/id_ed25519"},
	}
	for i := range ok {
		if err := ok[i].Validate(); err != nil {
			t.Errorf("%+v: %v", ok[i], err)
		}
	}
	if h := ok[1]; h.Addr != "2001:db8::1" {
		t.Errorf("ipv6 not normalised: %q", h.Addr)
	}
	bad := []HostConfig{
		{Addr: "", User: "root", Auth: AuthPassword, Password: "x"},
		{Addr: "a b", User: "root", Auth: AuthPassword, Password: "x"},
		{Addr: "-oProxyCommand=x", User: "root", Auth: AuthPassword, Password: "x"},
		{Addr: "h", Port: 70000, User: "root", Auth: AuthPassword, Password: "x"},
		{Addr: "h", User: "-x", Auth: AuthPassword, Password: "x"},
		{Addr: "h", User: "root", Auth: AuthPassword},
		{Addr: "h", User: "root", Auth: AuthKey},
		{Addr: "h", User: "root", Auth: AuthKey, KeyPEM: "not a key"},
		{Addr: "h", User: "root", Auth: "telnet"},
		{Addr: "h", User: "root", Auth: AuthPassword, Password: "x", HostKey: "garbage"},
	}
	for _, h := range bad {
		if err := h.Validate(); err == nil {
			t.Errorf("%+v should fail", h)
		}
	}
}

func TestSecretsApply(t *testing.T) {
	h := HostConfig{Password: "old", Passphrase: "pp"}
	Secrets{Password: "new", Clear: []string{"passphrase"}}.Apply(&h)
	if h.Password != "new" || h.Passphrase != "" {
		t.Errorf("%+v", h)
	}
	Secrets{}.Apply(&h)
	if h.Password != "new" {
		t.Error("empty secret should keep the old value")
	}
}

func TestCmdline(t *testing.T) {
	got := cmdline("-n", "firewall-cmd", []string{"--zone=public", "--add-rich-rule=rule family=\"ipv4\" accept", "it's"})
	if !strings.HasPrefix(got, "sudo -n -- env LC_ALL=C LANG=C LANGUAGE=C PATH=") {
		t.Errorf("prefix: %s", got)
	}
	if !strings.HasSuffix(got, ` firewall-cmd --zone=public '--add-rich-rule=rule family="ipv4" accept' 'it'\''s'`) {
		t.Errorf("args: %s", got)
	}
}
