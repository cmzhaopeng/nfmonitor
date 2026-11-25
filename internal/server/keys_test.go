package server

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nfmonitor/internal/remote"
)

func mustPrefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func TestLoadKey(t *testing.T) {
	data := t.TempDir()
	other := t.TempDir()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	t.Setenv(envKeyFile, "")
	t.Setenv(envKey, "")

	if _, _, err := LoadKey("", data); err == nil {
		t.Fatal("no key should fail")
	}
	// 放在数据目录里：拒绝
	in := filepath.Join(data, "master.key")
	os.WriteFile(in, []byte(base64.StdEncoding.EncodeToString(raw)), 0o600)
	if _, _, err := LoadKey(in, data); err == nil || !strings.Contains(err.Error(), "数据目录") {
		t.Fatalf("key inside data dir: %v", err)
	}
	for name, content := range map[string][]byte{"b64": []byte(base64.StdEncoding.EncodeToString(raw) + "\n"), "hex": []byte(hex.EncodeToString(raw)), "raw": raw} {
		p := filepath.Join(other, name)
		os.WriteFile(p, content, 0o600)
		k, _, err := LoadKey(p, data)
		if err != nil || string(k) != string(raw) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad := filepath.Join(other, "bad")
	os.WriteFile(bad, []byte("short"), 0o600)
	if _, _, err := LoadKey(bad, data); err == nil {
		t.Fatal("short key accepted")
	}
	t.Setenv(envKey, hex.EncodeToString(raw))
	k, src, err := LoadKey("", data)
	if err != nil || string(k) != string(raw) || !strings.Contains(src, envKey) || os.Getenv(envKey) != "" {
		t.Fatalf("env: %v %s", err, src)
	}
}

func TestStoreWithExternalKey(t *testing.T) {
	dir := t.TempDir()
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k2[0] = 1
	st, err := remote.OpenStoreWithKey(dir, k1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(remote.HostConfig{Addr: "10.0.0.1", User: "ops", Auth: remote.AuthPassword, Password: "pw-secret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secret.key")); !os.IsNotExist(err) {
		t.Fatal("secret.key must not be written with an external key")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "hosts.json"))
	if strings.Contains(string(b), "pw-secret") || !strings.Contains(string(b), "keyCheck") {
		t.Fatalf("hosts.json: %s", b)
	}
	if _, err := remote.OpenStoreWithKey(dir, k2); err == nil {
		t.Fatal("wrong key accepted")
	}
	st2, err := remote.OpenStoreWithKey(dir, k1)
	if err != nil || st2.List()[0].Password != "pw-secret" {
		t.Fatalf("reopen: %v", err)
	}
}

func TestUsersFile(t *testing.T) {
	dir := t.TempDir()
	u, _ := OpenUsers(dir)
	if err := u.Put("x", RoleAdmin, "short", true); err == nil {
		t.Fatal("short password accepted")
	}
	if err := u.Put("bad name", RoleAdmin, "long-enough-pw", true); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := u.Put("ops", "root", "long-enough-pw", true); err == nil {
		t.Fatal("bad role accepted")
	}
	if err := u.Put("ops", "", "long-enough-pw", true); err != nil {
		t.Fatal(err)
	}
	if x, _ := u.Get("ops"); x.Role != RoleViewer || strings.Contains(x.Hash, "long-enough") {
		t.Fatalf("user: %+v", x)
	}
	// 另一个进程（命令行）改了文件：运行中的服务能读到
	u2, _ := OpenUsers(dir)
	u2.Put("ops2", RoleAdmin, "another-password", true)
	if _, ok := u.Get("ops2"); !ok {
		t.Fatal("reload failed")
	}
	if st, _ := os.Stat(filepath.Join(dir, "users.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", st.Mode().Perm())
	}
}
