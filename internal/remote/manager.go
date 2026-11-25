package remote

import (
	"errors"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Manager 持有主机列表和每台主机的连接。
type Manager struct {
	store *Store
	mu    sync.Mutex
	hosts map[string]*Host
	// OnRemove 在主机被删除、配置被修改或被手动断开时调用（API 层借此清理该主机的采样状态）。
	OnRemove func(id string)
	// ServerMode 为真时（服务器版）只接受口令和粘贴的私钥：私钥文件路径和 ssh-agent 指向的是
	// 服务器上的文件 / 进程，不该由网页上的用户指定。
	ServerMode bool
}

// ErrServerAuth 是服务器版拒绝的认证方式。
var ErrServerAuth = errors.New("服务器版只支持口令或粘贴私钥内容（加密保存），不支持私钥文件路径和 ssh-agent")

func (m *Manager) checkAuth(cfg HostConfig) error {
	if m.ServerMode && (cfg.Auth == AuthAgent || (cfg.Auth == AuthKey && cfg.KeyPEM == "") || cfg.KeyPath != "") {
		return ErrServerAuth
	}
	return nil
}

func NewManager(store *Store) *Manager {
	return &Manager{store: store, hosts: map[string]*Host{}}
}

// HostView 是返回给界面的主机信息：不含任何机密，只标出哪些机密已保存。
type HostView struct {
	HostConfig
	Fingerprint     string   `json:"fingerprint"`
	HasPassword     bool     `json:"hasPassword"`
	HasKeyPEM       bool     `json:"hasKeyPem"`
	HasPassphrase   bool     `json:"hasPassphrase"`
	HasSudoPassword bool     `json:"hasSudoPassword"`
	Connected       bool     `json:"connected"`
	Manual          bool     `json:"manual"` // 用户手动断开，不会自动重连
	Error           string   `json:"error,omitempty"`
	Info            HostInfo `json:"info"`
}

func view(cfg HostConfig, h *Host) HostView {
	v := HostView{HostConfig: cfg, HasPassword: cfg.Password != "", HasKeyPEM: cfg.KeyPEM != "",
		HasPassphrase: cfg.Passphrase != "", HasSudoPassword: cfg.SudoPassword != ""}
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey)); err == nil {
		v.Fingerprint = ssh.FingerprintSHA256(k)
	}
	if h != nil {
		v.Connected, v.Error, v.Info = h.Status()
		v.Manual = h.Manual()
	}
	return v
}

// List 返回所有主机及连接状态。
func (m *Manager) List() []HostView {
	out := []HostView{}
	for _, cfg := range m.store.List() {
		m.mu.Lock()
		h := m.hosts[cfg.ID]
		m.mu.Unlock()
		out = append(out, view(cfg, h))
	}
	return out
}

// Configs 返回所有主机的配置（含机密，仅供本进程内部使用）。
func (m *Manager) Configs() []HostConfig { return m.store.List() }

// Get 返回一台主机的连接句柄（不会立即连接）。
func (m *Manager) Get(id string) (*Host, error) {
	cfg, ok := m.store.Get(id)
	if !ok {
		return nil, errors.New("主机不存在（可能已被删除）")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.hosts[id]
	if h == nil {
		h = newHost(cfg)
		m.hosts[id] = h
	}
	return h, nil
}

// Save 新增或更新主机；更新时断开旧连接，按新配置重新连接。
// cfg 里的机密字段为空表示沿用已保存的值（由 secrets 决定是否修改 / 清除）。
func (m *Manager) Save(cfg HostConfig, secrets Secrets) (HostView, error) {
	if cfg.ID != "" {
		old, ok := m.store.Get(cfg.ID)
		if !ok {
			return HostView{}, errors.New("主机不存在")
		}
		cfg.Password, cfg.KeyPEM, cfg.Passphrase, cfg.SudoPassword = old.Password, old.KeyPEM, old.Passphrase, old.SudoPassword
	}
	secrets.Apply(&cfg)
	if err := m.checkAuth(cfg); err != nil {
		return HostView{}, err
	}
	saved, err := m.store.Put(cfg)
	if err != nil {
		return HostView{}, err
	}
	m.forget(saved.ID)
	return view(saved, nil), nil
}

// Test 用一份（未保存的）配置连一次，返回探测结果。cfg.ID 非空时，没填的机密沿用已保存的值。
func (m *Manager) Test(cfg HostConfig, secrets Secrets) (HostInfo, error) {
	if cfg.ID != "" {
		if old, ok := m.store.Get(cfg.ID); ok {
			cfg.Password, cfg.KeyPEM, cfg.Passphrase, cfg.SudoPassword = old.Password, old.KeyPEM, old.Passphrase, old.SudoPassword
		}
	}
	secrets.Apply(&cfg)
	if err := m.checkAuth(cfg); err != nil {
		return HostInfo{}, err
	}
	if err := cfg.Validate(); err != nil {
		return HostInfo{}, err
	}
	h := newHost(cfg)
	defer h.Close()
	return h.Connect()
}

// Connect 立即连接一台已保存的主机（界面上的「连接」按钮）。
func (m *Manager) Connect(id string) (HostView, error) {
	h, err := m.Get(id)
	if err != nil {
		return HostView{}, err
	}
	_, cerr := h.Reconnect()
	cfg, _ := m.store.Get(id)
	return view(cfg, h), cerr
}

// Disconnect 断开一台主机（界面上的「断开」按钮）；之后不会自动重连，直到再调用 Connect。
func (m *Manager) Disconnect(id string) (HostView, error) {
	cfg, ok := m.store.Get(id)
	if !ok {
		return HostView{}, errors.New("主机不存在（可能已被删除）")
	}
	m.mu.Lock()
	h := m.hosts[id]
	m.mu.Unlock()
	if h == nil {
		return view(cfg, nil), nil
	}
	h.Disconnect()
	if m.OnRemove != nil {
		m.OnRemove(id) // 停掉该主机的采样
	}
	return view(cfg, h), nil
}

func (m *Manager) Delete(id string) error {
	if err := m.store.Delete(id); err != nil {
		return err
	}
	m.forget(id)
	return nil
}

func (m *Manager) forget(id string) {
	m.mu.Lock()
	h := m.hosts[id]
	delete(m.hosts, id)
	m.mu.Unlock()
	if h != nil {
		h.Close()
	}
	if m.OnRemove != nil {
		m.OnRemove(id)
	}
}

// Close 断开所有连接。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, h := range m.hosts {
		h.Close()
		delete(m.hosts, id)
	}
}
