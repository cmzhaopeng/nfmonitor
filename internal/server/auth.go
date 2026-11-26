package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// ---- 会话 ----

type session struct {
	user     string
	changed  time.Time // 登录时账号的口令修改时间：账号改了口令 / 被停用后会话失效
	created  time.Time
	lastSeen time.Time
	reauthAt time.Time // 最近一次再次输入口令确认的时间（危险操作要求在 reauthWindow 内）
	ip       string
}

type sessions struct {
	mu      sync.Mutex
	m       map[[32]byte]*session
	idle    time.Duration
	maxAge  time.Duration
	nowFunc func() time.Time
}

func newSessions(idle, maxAge time.Duration) *sessions {
	return &sessions{m: map[[32]byte]*session{}, idle: idle, maxAge: maxAge, nowFunc: time.Now}
}

// 服务端只存令牌的 SHA-256：内存被转储也拿不到能用的 cookie。
func tokenKey(tok string) [32]byte { return sha256.Sum256([]byte(tok)) }

func (s *sessions) create(u User, ip string) (string, *session) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	now := s.nowFunc()
	se := &session{user: u.Name, changed: u.Changed, created: now, lastSeen: now, reauthAt: now, ip: ip}
	s.mu.Lock()
	s.m[tokenKey(tok)] = se
	s.mu.Unlock()
	return tok, se
}

// get 取出有效会话并刷新最后活动时间；过期的顺手删掉。
func (s *sessions) get(tok string) *session {
	if tok == "" {
		return nil
	}
	k := tokenKey(tok)
	now := s.nowFunc()
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.m[k]
	if se == nil {
		return nil
	}
	if now.Sub(se.lastSeen) > s.idle || now.Sub(se.created) > s.maxAge {
		delete(s.m, k)
		return nil
	}
	se.lastSeen = now
	return se
}

func (s *sessions) delete(tok string) {
	s.mu.Lock()
	delete(s.m, tokenKey(tok))
	s.mu.Unlock()
}

func (s *sessions) markReauth(se *session) {
	s.mu.Lock()
	se.reauthAt = s.nowFunc()
	s.mu.Unlock()
}

func (s *sessions) reauthAge(se *session) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nowFunc().Sub(se.reauthAt)
}

func (s *sessions) gc() {
	now := s.nowFunc()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, se := range s.m {
		if now.Sub(se.lastSeen) > s.idle || now.Sub(se.created) > s.maxAge {
			delete(s.m, k)
		}
	}
}

// ---- 登录限速 ----
//
// 同一来源 IP 15 分钟内失败 ipMaxFails 次：封 15 分钟。
// 同一用户名连续失败 userMaxFails 次起：锁定 1、2、4 … 分钟，最长 1 小时（成功登录后清零）。

const (
	ipWindow     = 15 * time.Minute
	ipMaxFails   = 20
	userMaxFails = 5
	userMaxLock  = time.Hour
)

type failRec struct {
	n     int
	first time.Time
	until time.Time
}

type limiter struct {
	mu      sync.Mutex
	ip      map[string]*failRec
	user    map[string]*failRec
	nowFunc func() time.Time
}

func newLimiter() *limiter {
	return &limiter{ip: map[string]*failRec{}, user: map[string]*failRec{}, nowFunc: time.Now}
}

// blocked 返回还要等多久才能再试（0 = 可以试）。
func (l *limiter) blocked(ip, user string) time.Duration {
	now := l.nowFunc()
	l.mu.Lock()
	defer l.mu.Unlock()
	var wait time.Duration
	for _, r := range []*failRec{l.ip[ip], l.user[user]} {
		if r != nil && r.until.After(now) && r.until.Sub(now) > wait {
			wait = r.until.Sub(now)
		}
	}
	return wait
}

func (l *limiter) fail(ip, user string) {
	now := l.nowFunc()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.ip[ip]
	if r == nil || now.Sub(r.first) > ipWindow {
		r = &failRec{first: now}
		l.ip[ip] = r
	}
	r.n++
	if r.n >= ipMaxFails {
		r.until = now.Add(ipWindow)
	}
	if user == "" {
		return
	}
	u := l.user[user]
	if u == nil {
		u = &failRec{first: now}
		l.user[user] = u
	}
	u.n++
	if u.n >= userMaxFails {
		d := time.Minute << (u.n - userMaxFails)
		if d > userMaxLock || d <= 0 {
			d = userMaxLock
		}
		u.until = now.Add(d)
	}
}

func (l *limiter) success(user string) {
	l.mu.Lock()
	delete(l.user, user)
	l.mu.Unlock()
}

func (l *limiter) gc() {
	now := l.nowFunc()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, r := range l.ip {
		if now.Sub(r.first) > ipWindow && now.After(r.until) {
			delete(l.ip, k)
		}
	}
	for k, r := range l.user {
		if now.Sub(r.first) > 24*time.Hour && now.After(r.until) {
			delete(l.user, k)
		}
	}
}
