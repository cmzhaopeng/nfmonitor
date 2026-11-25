// Package server 是 nfmonitor 的服务器版（`nfmonitor server`）：部署在一台服务器上，
// 多个用户登录后集中查看、管理所有纳管主机。
//
// 它包在 internal/api 的接口外面，负责：
//   - 登录认证（账号存 users.json，bcrypt；会话 cookie：HttpOnly、SameSite=Strict、HTTPS 下 Secure）
//   - 角色：admin 可以纳管主机、修改防火墙；viewer 只读
//   - 危险操作（执行防火墙修改、保存 / 删除主机）要求最近 reauthWindow 内再次输入过口令
//   - 登录限速、跨站防护（Origin 校验 + 自定义请求头 + SameSite）、安全响应头
//   - 审计日志：登录、主机管理、防火墙修改都记录谁、从哪、对哪台主机、做了什么、结果如何
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const reauthWindow = 5 * time.Minute

// Options 是网关的配置。
type Options struct {
	API     http.Handler // internal/api 的接口
	Static  fs.FS        // 前端静态文件
	Users   *Users
	Audit   *Audit
	Version string

	// Secure 为真时 cookie 带 Secure（直接 HTTPS，或在做 TLS 终结的反向代理后面）。
	Secure bool
	// HSTS 为真时发 Strict-Transport-Security（直接 HTTPS 时）。
	HSTS bool
	// TrustedProxies 里的地址发来的请求，客户端 IP 取 X-Forwarded-For 的最后一项。
	TrustedProxies []netip.Prefix
	// AllowedOrigins 是除「与 Host 相同」之外还接受的 Origin（反向代理改写了 Host 时用）。
	AllowedOrigins []string

	SessionIdle   time.Duration
	SessionMaxAge time.Duration

	// HostName 把主机 ID 翻译成名称，写进审计日志。
	HostName func(id string) string
}

type Gateway struct {
	o    Options
	sess *sessions
	lim  *limiter
	stop chan struct{}
}

// 需要 admin 的修改类接口。
var adminPaths = map[string]bool{
	"/api/ufw/preview": true, "/api/ufw/apply": true,
	"/api/firewalld/preview": true, "/api/firewalld/apply": true,
	"/api/hosts/save": true, "/api/hosts/delete": true, "/api/hosts/test": true,
	"/api/hosts/probe": true, "/api/hosts/disconnect": true,
}

// 还要求最近再次输入过口令的危险操作。
var reauthPaths = map[string]bool{
	"/api/ufw/apply": true, "/api/firewalld/apply": true,
	"/api/hosts/save": true, "/api/hosts/delete": true,
}

// 服务器版不提供的接口（本机提权）。
var blockedPaths = map[string]bool{"/api/elevate": true}

func NewGateway(o Options) *Gateway {
	if o.SessionIdle == 0 {
		o.SessionIdle = 30 * time.Minute
	}
	if o.SessionMaxAge == 0 {
		o.SessionMaxAge = 12 * time.Hour
	}
	g := &Gateway{o: o, sess: newSessions(o.SessionIdle, o.SessionMaxAge), lim: newLimiter(), stop: make(chan struct{})}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				g.sess.gc()
				g.lim.gc()
			case <-g.stop:
				return
			}
		}
	}()
	return g
}

func (g *Gateway) Close() { close(g.stop) }

func (g *Gateway) cookieName() string {
	if g.o.Secure {
		return "__Host-nfm_session" // __Host- 前缀：必须 Secure、Path=/、不带 Domain
	}
	return "nfm_session"
}

// ServeHTTP 是服务器版的总入口。
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.securityHeaders(w)
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.FileServerFS(g.o.Static).ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && !g.originOK(r) {
		jsonErr(w, http.StatusForbidden, "跨站请求被拒绝", nil)
		return
	}
	switch r.URL.Path {
	case "/api/auth/login":
		g.login(w, r)
		return
	case "/api/auth/logout":
		g.logout(w, r)
		return
	}
	se, role := g.session(r)
	if se == nil {
		jsonErr(w, http.StatusUnauthorized, "未登录或登录已过期", map[string]any{"login": true})
		return
	}
	switch r.URL.Path {
	case "/api/session":
		writeJSON(w, map[string]any{"mode": "server", "local": false, "version": g.o.Version, "user": se.user, "role": role,
			"canWrite": role == RoleAdmin, "idleMinutes": int(g.o.SessionIdle.Minutes())})
		return
	case "/api/auth/reauth":
		g.reauth(w, r, se)
		return
	case "/api/audit":
		if role != RoleAdmin {
			jsonErr(w, http.StatusForbidden, "只有管理员能查看审计日志", nil)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 200
		}
		list, err := g.o.Audit.Recent(limit)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error(), nil)
			return
		}
		writeJSON(w, map[string]any{"entries": list})
		return
	}
	if blockedPaths[r.URL.Path] {
		jsonErr(w, http.StatusForbidden, "服务器版不提供这个功能", nil)
		return
	}
	if r.Method == http.MethodGet {
		g.o.API.ServeHTTP(w, r)
		return
	}
	// 以下是修改类请求：都记审计。
	action := strings.TrimPrefix(r.URL.Path, "/api/")
	entry := AuditEntry{User: se.user, IP: g.clientIP(r), Action: action, Host: r.URL.Query().Get("host")}
	if entry.Host != "" && g.o.HostName != nil {
		entry.HostName = g.o.HostName(entry.Host)
	}
	if adminPaths[r.URL.Path] && role != RoleAdmin {
		entry.Result, entry.Error = "denied", "只读账号"
		g.o.Audit.Log(entry)
		jsonErr(w, http.StatusForbidden, "只读账号不能修改", nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		jsonErr(w, http.StatusRequestEntityTooLarge, "请求体太大", nil)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	entry.Detail = sanitize(body)
	if id, ok := entry.Detail["id"].(string); ok && entry.Host == "" && strings.HasPrefix(action, "hosts/") {
		entry.Host = id
		if g.o.HostName != nil {
			entry.HostName = g.o.HostName(id)
		}
	}
	if reauthPaths[r.URL.Path] && g.sess.reauthAge(se) > reauthWindow {
		entry.Result, entry.Error = "denied", "需要再次输入口令"
		g.o.Audit.Log(entry)
		jsonErr(w, http.StatusForbidden, "这是危险操作，请再次输入口令确认", map[string]any{"reauth": true})
		return
	}
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	g.o.API.ServeHTTP(rec, r)
	entry.Result = "ok"
	if rec.status >= 400 {
		entry.Result = "error"
	}
	var resp map[string]any
	if json.Unmarshal(rec.buf.Bytes(), &resp) == nil {
		if e, ok := resp["error"].(string); ok {
			entry.Error = e
		}
		if resp["lockout"] == true {
			entry.Result = "denied"
			entry.Error = "防失联拦截：" + entry.Error
		}
		// 防火墙修改：记下实际执行的命令
		if cmds, ok := resp["commands"]; ok && strings.HasSuffix(action, "/apply") {
			if entry.Detail == nil {
				entry.Detail = map[string]any{}
			}
			entry.Detail["commands"] = cmds
			entry.Detail["executed"] = resp["executed"]
		}
		if action == "hosts/save" && entry.Host == "" {
			if id, ok := resp["id"].(string); ok {
				entry.Host = id
			}
		}
	}
	if action == "hosts/save" && entry.HostName == "" {
		if n, ok := entry.Detail["name"].(string); ok {
			entry.HostName = n
		}
	}
	g.o.Audit.Log(entry)
}

// session 从 cookie 取出有效会话和账号当前的角色；账号被删除、停用或改了口令时视为无效。
func (g *Gateway) session(r *http.Request) (*session, string) {
	c, err := r.Cookie(g.cookieName())
	if err != nil {
		return nil, ""
	}
	se := g.sess.get(c.Value)
	if se == nil {
		return nil, ""
	}
	u, ok := g.o.Users.Get(se.user)
	if !ok || u.Disabled || !u.Changed.Equal(se.changed) {
		g.sess.delete(c.Value)
		return nil, ""
	}
	return se, u.Role // 角色以账号文件为准，改了立即生效
}

type loginReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func (g *Gateway) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !jsonReq(r) {
		jsonErr(w, http.StatusBadRequest, "bad request", nil)
		return
	}
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request", nil)
		return
	}
	ip := g.clientIP(r)
	entry := AuditEntry{User: req.User, IP: ip, Action: "login"}
	if !reUserName.MatchString(req.User) {
		req.User = ""
	}
	if wait := g.lim.blocked(ip, req.User); wait > 0 {
		entry.Result, entry.Error = "denied", "尝试次数过多"
		g.o.Audit.Log(entry)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		jsonErr(w, http.StatusTooManyRequests, fmt.Sprintf("尝试次数过多，请 %d 分钟后再试", int(wait.Minutes())+1), nil)
		return
	}
	u, ok := g.o.Users.Verify(req.User, req.Password)
	if !ok {
		g.lim.fail(ip, req.User)
		entry.Result, entry.Error = "error", "用户名或口令不对"
		g.o.Audit.Log(entry)
		jsonErr(w, http.StatusUnauthorized, "用户名或口令不对", nil)
		return
	}
	g.lim.success(u.Name)
	// 换发新令牌（防会话固定）：旧 cookie 作废
	if c, err := r.Cookie(g.cookieName()); err == nil {
		g.sess.delete(c.Value)
	}
	tok, _ := g.sess.create(u, ip)
	http.SetCookie(w, &http.Cookie{Name: g.cookieName(), Value: tok, Path: "/", HttpOnly: true, Secure: g.o.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(g.o.SessionMaxAge.Seconds())})
	entry.Result = "ok"
	g.o.Audit.Log(entry)
	writeJSON(w, map[string]any{"user": u.Name, "role": u.Role})
}

func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	if se, _ := g.session(r); se != nil {
		c, _ := r.Cookie(g.cookieName())
		g.sess.delete(c.Value)
		g.o.Audit.Log(AuditEntry{User: se.user, IP: g.clientIP(r), Action: "logout", Result: "ok"})
	}
	http.SetCookie(w, &http.Cookie{Name: g.cookieName(), Value: "", Path: "/", HttpOnly: true, Secure: g.o.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, map[string]any{"ok": true})
}

func (g *Gateway) reauth(w http.ResponseWriter, r *http.Request, se *session) {
	if r.Method != http.MethodPost || !jsonReq(r) {
		jsonErr(w, http.StatusBadRequest, "bad request", nil)
		return
	}
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request", nil)
		return
	}
	ip := g.clientIP(r)
	entry := AuditEntry{User: se.user, IP: ip, Action: "reauth"}
	if wait := g.lim.blocked(ip, se.user); wait > 0 {
		entry.Result, entry.Error = "denied", "尝试次数过多"
		g.o.Audit.Log(entry)
		jsonErr(w, http.StatusTooManyRequests, fmt.Sprintf("尝试次数过多，请 %d 分钟后再试", int(wait.Minutes())+1), nil)
		return
	}
	if _, ok := g.o.Users.Verify(se.user, req.Password); !ok {
		g.lim.fail(ip, se.user)
		entry.Result, entry.Error = "error", "口令不对"
		g.o.Audit.Log(entry)
		jsonErr(w, http.StatusUnauthorized, "口令不对", nil)
		return
	}
	g.lim.success(se.user)
	g.sess.markReauth(se)
	entry.Result = "ok"
	g.o.Audit.Log(entry)
	writeJSON(w, map[string]any{"ok": true, "validMinutes": int(reauthWindow.Minutes())})
}

// originOK：非 GET 请求必须带 Origin，且与请求的 Host（或配置的 AllowedOrigins）一致。
// 再加上接口本身要求的自定义请求头 + JSON 和 SameSite=Strict 的 cookie，跨站页面无法代发请求。
func (g *Gateway) originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return false
	}
	for _, a := range g.o.AllowedOrigins {
		if strings.EqualFold(strings.TrimRight(a, "/"), o) {
			return true
		}
	}
	u, err := url.Parse(o)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

func (g *Gateway) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.Unmap()
	for _, p := range g.o.TrustedProxies {
		if p.Contains(ip) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				if c, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
					return c.Unmap().String()
				}
			}
			break
		}
	}
	return ip.String()
}

func (g *Gateway) securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if g.o.HSTS {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
}

// sanitize 把请求体转成审计用的结构：去掉所有机密字段。
func sanitize(body []byte) map[string]any {
	var m map[string]any
	if len(body) == 0 || json.Unmarshal(body, &m) != nil {
		return nil
	}
	scrub(m)
	return m
}

var secretKeys = map[string]bool{"secrets": true, "password": true, "keypem": true, "passphrase": true, "sudopassword": true}

func scrub(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			if secretKeys[strings.ToLower(k)] {
				if k == "secrets" {
					// 只记录改了哪些机密，不记内容
					if sm, ok := vv.(map[string]any); ok {
						var changed []string
						for sk, sv := range sm {
							if s, ok := sv.(string); ok && s != "" {
								changed = append(changed, sk)
							}
						}
						if clr, ok := sm["clear"]; ok {
							x["secretsCleared"] = clr
						}
						if len(changed) > 0 {
							x["secretsChanged"] = changed
						}
					}
				}
				delete(x, k)
				continue
			}
			scrub(vv)
		}
	case []any:
		for _, vv := range x {
			scrub(vv)
		}
	}
}

func jsonReq(r *http.Request) bool {
	return r.Header.Get("X-Nfmonitor") != "" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string, extra map[string]any) {
	body := map[string]any{"error": msg}
	for k, v := range extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// recorder 记下状态码和响应体（审计要用），同时照常写给客户端。
type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.buf.Len() < 256<<10 {
		r.buf.Write(b)
	}
	return r.ResponseWriter.Write(b)
}
