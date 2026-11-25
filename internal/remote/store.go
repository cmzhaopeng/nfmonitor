// Package remote 管理要监控的远程主机：连接配置的持久化（口令加密保存）、SSH 连接，
// 以及把远程主机包装成 netinfo.Sys，让采集层像读本机一样读远程主机。
package remote

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// 认证方式。
const (
	AuthPassword = "password" // 口令
	AuthKey      = "key"      // 私钥（文件路径或粘贴的内容）
	AuthAgent    = "agent"    // ssh-agent（SSH_AUTH_SOCK）
)

// HostConfig 是一台远程主机的连接配置。机密字段（口令、私钥内容、私钥口令、sudo 口令）
// 存盘时加密，接口也从不回传。
type HostConfig struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Addr    string `json:"addr"` // IP 或主机名
	Port    int    `json:"port"`
	User    string `json:"user"`
	Auth    string `json:"auth"`              // password | key | agent
	KeyPath string `json:"keyPath,omitempty"` // auth=key 且没有粘贴私钥时使用
	HostKey string `json:"hostKey,omitempty"` // 已信任的主机公钥（authorized_keys 格式）

	Password     string `json:"-"`
	KeyPEM       string `json:"-"`
	Passphrase   string `json:"-"`
	SudoPassword string `json:"-"` // 为空且 auth=password 时，sudo 用登录口令
}

// Secrets 是前端提交时可能带上的机密；空串表示「不修改」，Clear 里列出的字段表示「清除」。
type Secrets struct {
	Password     string   `json:"password,omitempty"`
	KeyPEM       string   `json:"keyPem,omitempty"`
	Passphrase   string   `json:"passphrase,omitempty"`
	SudoPassword string   `json:"sudoPassword,omitempty"`
	Clear        []string `json:"clear,omitempty"` // password keyPem passphrase sudoPassword
}

// Apply 把提交的机密合并进配置。
func (s Secrets) Apply(h *HostConfig) {
	for _, f := range []struct {
		name string
		v    string
		dst  *string
	}{{"password", s.Password, &h.Password}, {"keyPem", s.KeyPEM, &h.KeyPEM}, {"passphrase", s.Passphrase, &h.Passphrase}, {"sudoPassword", s.SudoPassword, &h.SudoPassword}} {
		for _, c := range s.Clear {
			if c == f.name {
				*f.dst = ""
			}
		}
		if f.v != "" {
			*f.dst = f.v
		}
	}
}

var (
	reHostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\.?$`)
	reUser     = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}$`)
	reID       = regexp.MustCompile(`^[a-f0-9]{12}$`)
)

// Validate 校验并规范化配置。
func (h *HostConfig) Validate() error {
	h.Name = strings.TrimSpace(h.Name)
	h.Addr = strings.TrimSpace(h.Addr)
	h.User = strings.TrimSpace(h.User)
	h.KeyPath = strings.TrimSpace(h.KeyPath)
	if h.Addr == "" {
		return errors.New("请填写主机地址")
	}
	if a, err := netip.ParseAddr(strings.Trim(h.Addr, "[]")); err == nil {
		if a.Zone() != "" {
			return errors.New("暂不支持带网卡后缀（%）的链路本地地址")
		}
		h.Addr = a.String()
	} else if !reHostname.MatchString(h.Addr) || len(h.Addr) > 253 {
		return fmt.Errorf("主机地址无效: %q", h.Addr)
	}
	if h.Port == 0 {
		h.Port = 22
	}
	if h.Port < 1 || h.Port > 65535 {
		return fmt.Errorf("端口无效: %d", h.Port)
	}
	if !reUser.MatchString(h.User) {
		return fmt.Errorf("用户名无效: %q", h.User)
	}
	if h.Name == "" {
		h.Name = h.User + "@" + h.Addr
	}
	if len([]rune(h.Name)) > 64 {
		return errors.New("名称太长（最多 64 个字）")
	}
	for _, c := range h.Name {
		if unicode.IsControl(c) {
			return errors.New("名称里不能有控制字符")
		}
	}
	switch h.Auth {
	case AuthPassword:
		if h.Password == "" {
			return errors.New("请填写登录口令")
		}
	case AuthKey:
		if h.KeyPEM == "" && h.KeyPath == "" {
			return errors.New("请填写私钥文件路径，或粘贴私钥内容")
		}
		if h.KeyPath != "" {
			p, err := expandHome(h.KeyPath)
			if err != nil {
				return err
			}
			h.KeyPath = p
		}
		if h.KeyPEM != "" {
			if _, err := parseKey([]byte(h.KeyPEM), h.Passphrase); err != nil {
				return err
			}
		}
	case AuthAgent:
		if os.Getenv("SSH_AUTH_SOCK") == "" {
			return errors.New("当前环境没有 ssh-agent（SSH_AUTH_SOCK 未设置）")
		}
	default:
		return fmt.Errorf("认证方式无效: %q", h.Auth)
	}
	if h.HostKey != "" {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.HostKey))
		if err != nil {
			return fmt.Errorf("主机公钥无效: %w", err)
		}
		h.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	}
	return nil
}

func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("私钥路径要写绝对路径（或以 ~/ 开头）")
	}
	return filepath.Clean(p), nil
}

// ---- 持久化 ----

// 存盘格式：机密字段是 AES-256-GCM 密文，密钥是同目录下的 secret.key。
type storedHost struct {
	HostConfig
	Password     string `json:"password,omitempty"`
	KeyPEM       string `json:"keyPem,omitempty"`
	Passphrase   string `json:"passphrase,omitempty"`
	SudoPassword string `json:"sudoPassword,omitempty"`
}

type storeFile struct {
	Version int          `json:"version"`
	Hosts   []storedHost `json:"hosts"`
}

// Store 保存主机列表：<配置目录>/nfmonitor/hosts.json（0600），目录 0700。
type Store struct {
	dir   string
	mu    sync.Mutex
	hosts []HostConfig
	key   []byte
}

// DefaultDir 是 $XDG_CONFIG_HOME/nfmonitor（通常 ~/.config/nfmonitor）。
func DefaultDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "nfmonitor"), nil
}

// OpenStore 读取 dir 下的主机列表（文件不存在时为空列表）。
func OpenStore(dir string) (*Store, error) {
	s := &Store{dir: dir}
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	// 文件权限被放宽过就收回来：里面是加密的口令，但也不该让别人读到。
	if st, err := os.Stat(s.path()); err == nil && st.Mode().Perm()&0o077 != 0 {
		os.Chmod(s.path(), 0o600)
	}
	var f storeFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s 格式错误: %w", s.path(), err)
	}
	for _, sh := range f.Hosts {
		h := sh.HostConfig
		for _, x := range []struct {
			name, enc string
			dst       *string
		}{{"password", sh.Password, &h.Password}, {"keyPem", sh.KeyPEM, &h.KeyPEM}, {"passphrase", sh.Passphrase, &h.Passphrase}, {"sudoPassword", sh.SudoPassword, &h.SudoPassword}} {
			if x.enc == "" {
				continue
			}
			v, err := s.decrypt(h.ID, x.name, x.enc)
			if err != nil {
				return nil, fmt.Errorf("主机 %s 的%s无法解密（secret.key 是否被替换？）: %w", h.Name, x.name, err)
			}
			*x.dst = v
		}
		s.hosts = append(s.hosts, h)
	}
	return s, nil
}

func (s *Store) path() string    { return filepath.Join(s.dir, "hosts.json") }
func (s *Store) keyPath() string { return filepath.Join(s.dir, "secret.key") }

// List 返回所有主机（含机密，仅供本进程内部使用）。
func (s *Store) List() []HostConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]HostConfig(nil), s.hosts...)
}

func (s *Store) Get(id string) (HostConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hosts {
		if h.ID == id {
			return h, true
		}
	}
	return HostConfig{}, false
}

// Put 新增（ID 为空）或更新一台主机。
func (s *Store) Put(h HostConfig) (HostConfig, error) {
	if err := h.Validate(); err != nil {
		return h, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	if h.ID == "" {
		b := make([]byte, 6)
		rand.Read(b)
		h.ID = hex.EncodeToString(b)
	} else {
		if !reID.MatchString(h.ID) {
			return h, errors.New("主机 ID 无效")
		}
		for i, x := range s.hosts {
			if x.ID == h.ID {
				idx = i
			}
		}
		if idx < 0 {
			return h, errors.New("主机不存在")
		}
	}
	next := append([]HostConfig(nil), s.hosts...)
	if idx < 0 {
		next = append(next, h)
	} else {
		next[idx] = h
	}
	if err := s.save(next); err != nil {
		return h, err
	}
	s.hosts = next
	return h, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]HostConfig, 0, len(s.hosts))
	for _, h := range s.hosts {
		if h.ID != id {
			next = append(next, h)
		}
	}
	if len(next) == len(s.hosts) {
		return errors.New("主机不存在")
	}
	if err := s.save(next); err != nil {
		return err
	}
	s.hosts = next
	return nil
}

func (s *Store) save(hosts []HostConfig) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	f := storeFile{Version: 1, Hosts: []storedHost{}}
	for _, h := range hosts {
		sh := storedHost{HostConfig: h}
		for _, x := range []struct {
			name, v string
			dst     *string
		}{{"password", h.Password, &sh.Password}, {"keyPem", h.KeyPEM, &sh.KeyPEM}, {"passphrase", h.Passphrase, &sh.Passphrase}, {"sudoPassword", h.SudoPassword, &sh.SudoPassword}} {
			if x.v == "" {
				continue
			}
			enc, err := s.encrypt(h.ID, x.name, x.v)
			if err != nil {
				return err
			}
			*x.dst = enc
		}
		f.Hosts = append(f.Hosts, sh)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(), b)
}

func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ---- 加密 ----

func (s *Store) loadKey(create bool) ([]byte, error) {
	if s.key != nil {
		return s.key, nil
	}
	b, err := os.ReadFile(s.keyPath())
	if err == nil && len(b) == 32 {
		s.key = b
		return b, nil
	}
	if err == nil {
		return nil, errors.New("secret.key 长度不对")
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(s.keyPath(), b); err != nil {
		return nil, err
	}
	s.key = b
	return b, nil
}

func (s *Store) aead(create bool) (cipher.AEAD, error) {
	k, err := s.loadKey(create)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// 附加数据绑定「哪台主机的哪个字段」，密文不能被挪到别处用。
func aad(id, field string) []byte { return []byte("nfmonitor/v1/" + id + "/" + field) }

func (s *Store) encrypt(id, field, v string) (string, error) {
	g, err := s.aead(true)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := g.Seal(nonce, nonce, []byte(v), aad(id, field))
	return "v1:" + base64.StdEncoding.EncodeToString(ct), nil
}

func (s *Store) decrypt(id, field, enc string) (string, error) {
	raw, ok := strings.CutPrefix(enc, "v1:")
	if !ok {
		return "", errors.New("未知的加密格式")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	g, err := s.aead(false)
	if err != nil {
		return "", err
	}
	if len(b) < g.NonceSize() {
		return "", errors.New("密文太短")
	}
	pt, err := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], aad(id, field))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
