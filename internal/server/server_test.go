package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type fakeAPI struct{ last string }

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.last = string(b)
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/ufw/apply":
		w.Write([]byte(`{"commands":[["ufw","allow","22/tcp"]],"executed":true}`))
	case "/api/hosts/delete":
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"主机不存在"}`))
	default:
		w.Write([]byte(`{"ok":true}`))
	}
}

func newGW(t *testing.T) (*Gateway, *fakeAPI, string) {
	dir := t.TempDir()
	u, err := OpenUsers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Put("alice", RoleAdmin, "alice-password-1", true); err != nil {
		t.Fatal(err)
	}
	if err := u.Put("bob", RoleViewer, "bob-password-12", true); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	a.stdout = nil
	t.Cleanup(a.Close)
	api := &fakeAPI{}
	g := NewGateway(Options{API: api, Static: fstest.MapFS{"index.html": {Data: []byte("<html>")}}, Users: u, Audit: a, Version: "t",
		HostName: func(id string) string { return "web-" + id }})
	t.Cleanup(g.Close)
	return g, api, dir
}

type client struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func (c *client) do(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://nfm.test"+path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:5555"
	if method != "GET" {
		req.Header.Set("Origin", "http://nfm.test")
		req.Header.Set("X-Nfmonitor", "1")
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			c.cookie = nil
		} else {
			c.cookie = ck
		}
	}
	return rec
}

func (c *client) login(user, pw string) int {
	return c.do("POST", "/api/auth/login", `{"user":"`+user+`","password":"`+pw+`"}`, nil).Code
}

func TestLoginAndAccess(t *testing.T) {
	g, api, dir := newGW(t)
	c := &client{t: t, h: g}

	// 静态页不需要登录，带安全响应头
	rec := c.do("GET", "/", "", nil)
	if rec.Code != 200 || rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("static: %d %v", rec.Code, rec.Header())
	}
	// 未登录的接口：401
	if rec := c.do("GET", "/api/links?host=x", "", nil); rec.Code != 401 || !strings.Contains(rec.Body.String(), `"login":true`) {
		t.Fatalf("unauth: %d %s", rec.Code, rec.Body)
	}
	if code := c.login("alice", "wrong-password"); code != 401 {
		t.Fatalf("bad login: %d", code)
	}
	if code := c.login("alice", "alice-password-1"); code != 200 || c.cookie == nil {
		t.Fatalf("login: %d", code)
	}
	if !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags: %+v", c.cookie)
	}
	rec = c.do("GET", "/api/session", "", nil)
	var s map[string]any
	json.Unmarshal(rec.Body.Bytes(), &s)
	if s["user"] != "alice" || s["role"] != RoleAdmin || s["canWrite"] != true {
		t.Fatalf("session: %s", rec.Body)
	}
	// 跨站：缺 Origin / Origin 不同都拒绝
	if rec := c.do("POST", "/api/ufw/apply?host=h1", `{}`, map[string]string{"Origin": ""}); rec.Code != 403 {
		t.Fatalf("no origin: %d", rec.Code)
	}
	if rec := c.do("POST", "/api/ufw/apply?host=h1", `{}`, map[string]string{"Origin": "https://evil.example"}); rec.Code != 403 {
		t.Fatalf("evil origin: %d", rec.Code)
	}
	// 刚登录：可以直接执行危险操作，审计里有命令、没有机密
	rec = c.do("POST", "/api/ufw/apply?host=h1", `{"op":"add","rule":{"dport":"22"}}`, nil)
	if rec.Code != 200 {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	rec = c.do("POST", "/api/hosts/save", `{"name":"db","addr":"10.0.0.5","user":"ops","auth":"password","secrets":{"password":"super-secret-pw"}}`, nil)
	if rec.Code != 200 || !strings.Contains(api.last, "super-secret-pw") {
		t.Fatalf("save: %d %s / api got %q", rec.Code, rec.Body, api.last)
	}
	// 服务器版不提供本机提权
	if rec := c.do("POST", "/api/elevate", ``, nil); rec.Code != 403 {
		t.Fatalf("elevate: %d", rec.Code)
	}
	// 退出后会话失效
	c.do("POST", "/api/auth/logout", ``, nil)
	if rec := c.do("GET", "/api/session", "", nil); rec.Code != 401 {
		t.Fatalf("after logout: %d", rec.Code)
	}

	b, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	log := string(b)
	if strings.Contains(log, "super-secret-pw") || strings.Contains(log, "alice-password-1") {
		t.Fatal("secret in audit log")
	}
	for _, want := range []string{`"action":"login","result":"error"`, `"action":"ufw/apply","host":"h1","hostName":"web-h1","result":"ok"`, `"commands":[["ufw","allow","22/tcp"]]`, `"secretsChanged":["password"]`, `"action":"logout"`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %s\n%s", want, log)
		}
	}
	list, err := g.o.Audit.Recent(2)
	if err != nil || len(list) != 2 || list[0].Action != "logout" {
		t.Fatalf("recent: %v %+v", err, list)
	}
}

func TestViewerAndReauth(t *testing.T) {
	g, _, _ := newGW(t)
	v := &client{t: t, h: g}
	if code := v.login("bob", "bob-password-12"); code != 200 {
		t.Fatal(code)
	}
	if rec := v.do("GET", "/api/fleet", "", nil); rec.Code != 200 {
		t.Fatalf("viewer read: %d", rec.Code)
	}
	if rec := v.do("POST", "/api/hosts/connect", `{"id":"h1"}`, nil); rec.Code != 200 {
		t.Fatalf("viewer connect: %d", rec.Code)
	}
	for _, p := range []string{"/api/ufw/apply", "/api/hosts/save", "/api/hosts/delete", "/api/firewalld/preview"} {
		if rec := v.do("POST", p, `{}`, nil); rec.Code != 403 {
			t.Fatalf("viewer %s: %d", p, rec.Code)
		}
	}
	if rec := v.do("GET", "/api/audit", "", nil); rec.Code != 403 {
		t.Fatalf("viewer audit: %d", rec.Code)
	}

	// 危险操作：登录超过 5 分钟后要求再次输入口令
	a := &client{t: t, h: g}
	a.login("alice", "alice-password-1")
	now := time.Now()
	g.sess.nowFunc = func() time.Time { return now.Add(6 * time.Minute) }
	rec := a.do("POST", "/api/hosts/delete", `{"id":"h1"}`, nil)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"reauth":true`) {
		t.Fatalf("need reauth: %d %s", rec.Code, rec.Body)
	}
	// 只读的预览不要求
	if rec := a.do("POST", "/api/ufw/preview", `{}`, nil); rec.Code != 200 {
		t.Fatalf("preview: %d", rec.Code)
	}
	if rec := a.do("POST", "/api/auth/reauth", `{"password":"nope-nope-nope"}`, nil); rec.Code != 401 {
		t.Fatalf("bad reauth: %d", rec.Code)
	}
	if rec := a.do("POST", "/api/auth/reauth", `{"password":"alice-password-1"}`, nil); rec.Code != 200 {
		t.Fatalf("reauth: %d %s", rec.Code, rec.Body)
	}
	rec = a.do("POST", "/api/hosts/delete", `{"id":"h1"}`, nil)
	if rec.Code != 500 { // fakeAPI 返回错误：应原样透传并记为 error
		t.Fatalf("delete after reauth: %d %s", rec.Code, rec.Body)
	}
	// 会话空闲超时
	g.sess.nowFunc = func() time.Time { return now.Add(time.Hour) }
	if rec := a.do("GET", "/api/session", "", nil); rec.Code != 401 {
		t.Fatalf("idle: %d", rec.Code)
	}
}

func TestPasswordChangeKillsSessions(t *testing.T) {
	g, _, _ := newGW(t)
	c := &client{t: t, h: g}
	c.login("alice", "alice-password-1")
	time.Sleep(1100 * time.Millisecond) // Changed 精确到秒
	if err := g.o.Users.Put("alice", "", "alice-password-2", false); err != nil {
		t.Fatal(err)
	}
	if rec := c.do("GET", "/api/session", "", nil); rec.Code != 401 {
		t.Fatalf("old session still valid: %d", rec.Code)
	}
	c.login("alice", "alice-password-2")
	if err := g.o.Users.Put("alice", RoleViewer, "", false); err != nil {
		t.Fatal(err)
	}
	if rec := c.do("POST", "/api/hosts/save", `{}`, nil); rec.Code != 403 {
		t.Fatalf("role change not applied: %d", rec.Code)
	}
	if err := g.o.Users.SetDisabled("alice", true); err != nil {
		t.Fatal(err)
	}
	if rec := c.do("GET", "/api/session", "", nil); rec.Code != 401 {
		t.Fatalf("disabled user session: %d", rec.Code)
	}
	if code := c.login("alice", "alice-password-2"); code != 401 {
		t.Fatalf("disabled login: %d", code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	g, _, _ := newGW(t)
	c := &client{t: t, h: g}
	for i := 0; i < userMaxFails; i++ {
		if code := c.login("alice", "wrong-password"); code != 401 {
			t.Fatalf("try %d: %d", i, code)
		}
	}
	// 锁定期间口令对了也不行
	if code := c.login("alice", "alice-password-1"); code != 429 {
		t.Fatalf("locked: %d", code)
	}
	now := time.Now()
	g.lim.nowFunc = func() time.Time { return now.Add(2 * time.Minute) }
	if code := c.login("alice", "alice-password-1"); code != 200 {
		t.Fatalf("after lock: %d", code)
	}
}

func TestClientIPBehindProxy(t *testing.T) {
	g, _, _ := newGW(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
	if ip := g.clientIP(r); ip != "127.0.0.1" {
		t.Fatalf("untrusted proxy: %s", ip)
	}
	g.o.TrustedProxies = mustPrefixes("127.0.0.1/32")
	if ip := g.clientIP(r); ip != "198.51.100.7" {
		t.Fatalf("trusted proxy: %s", ip)
	}
}
