package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// 角色：admin 能纳管主机、修改防火墙；viewer 只能看。
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

const (
	bcryptCost     = 12
	minPasswordLen = 10
)

// User 是一个登录账号。口令只存 bcrypt 散列。
type User struct {
	Name     string    `json:"name"`
	Hash     string    `json:"hash"`
	Role     string    `json:"role"`
	Disabled bool      `json:"disabled,omitempty"`
	Created  time.Time `json:"created"`
	Changed  time.Time `json:"changed"` // 口令最后修改时间：修改后旧会话失效
}

var reUserName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// Users 是 <数据目录>/users.json。服务运行中用命令行增删改账号也能生效：每次读取时比对文件修改时间。
type Users struct {
	path  string
	mu    sync.Mutex
	users map[string]User
	mtime time.Time
	size  int64
}

func OpenUsers(dir string) (*Users, error) {
	u := &Users{path: filepath.Join(dir, "users.json"), users: map[string]User{}}
	if err := u.reload(true); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *Users) reload(force bool) error {
	st, err := os.Stat(u.path)
	if errors.Is(err, os.ErrNotExist) {
		u.users, u.mtime, u.size = map[string]User{}, time.Time{}, 0
		return nil
	}
	if err != nil {
		return err
	}
	if !force && st.ModTime().Equal(u.mtime) && st.Size() == u.size {
		return nil
	}
	b, err := os.ReadFile(u.path)
	if err != nil {
		return err
	}
	var list []User
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("%s 格式错误: %w", u.path, err)
	}
	m := map[string]User{}
	for _, x := range list {
		m[x.Name] = x
	}
	u.users, u.mtime, u.size = m, st.ModTime(), st.Size()
	return nil
}

// Get 返回账号（文件变了会先重新读）。
func (u *Users) Get(name string) (User, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.reload(false); err != nil {
		return User{}, false
	}
	x, ok := u.users[name]
	return x, ok
}

func (u *Users) List() []User {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reload(false)
	out := make([]User, 0, len(u.users))
	for _, x := range u.users {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (u *Users) Count() int { return len(u.List()) }

// CheckPassword 校验口令强度（只做最基本的要求）。
func CheckPassword(pw string) error {
	if utf8.RuneCountInString(pw) < minPasswordLen {
		return fmt.Errorf("口令至少 %d 个字符", minPasswordLen)
	}
	if len(pw) > 72 {
		return errors.New("口令最长 72 字节")
	}
	return nil
}

// Put 新增或更新账号；password 非空时重设口令。
func (u *Users) Put(name, role, password string, create bool) error {
	if !reUserName.MatchString(name) {
		return fmt.Errorf("用户名无效: %q（字母数字开头，可含 . _ @ -，最长 64）", name)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.reload(true); err != nil {
		return err
	}
	x, exists := u.users[name]
	if create && exists {
		return fmt.Errorf("用户 %s 已存在", name)
	}
	if !create && !exists {
		return fmt.Errorf("用户 %s 不存在", name)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if !exists {
		x = User{Name: name, Created: now}
	}
	if role != "" {
		if role != RoleAdmin && role != RoleViewer {
			return fmt.Errorf("角色只能是 %s 或 %s", RoleAdmin, RoleViewer)
		}
		x.Role = role
	}
	if x.Role == "" {
		x.Role = RoleViewer
	}
	if password != "" {
		if err := CheckPassword(password); err != nil {
			return err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
		if err != nil {
			return err
		}
		x.Hash, x.Changed = string(h), now
	}
	if x.Hash == "" {
		return errors.New("请设置口令")
	}
	next := map[string]User{}
	for k, v := range u.users {
		next[k] = v
	}
	next[name] = x
	return u.save(next)
}

// SetDisabled 停用 / 启用账号。
func (u *Users) SetDisabled(name string, disabled bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.reload(true); err != nil {
		return err
	}
	x, ok := u.users[name]
	if !ok {
		return fmt.Errorf("用户 %s 不存在", name)
	}
	x.Disabled = disabled
	x.Changed = time.Now().UTC().Truncate(time.Second) // 让已登录的会话失效
	next := map[string]User{}
	for k, v := range u.users {
		next[k] = v
	}
	next[name] = x
	return u.save(next)
}

func (u *Users) Delete(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.reload(true); err != nil {
		return err
	}
	if _, ok := u.users[name]; !ok {
		return fmt.Errorf("用户 %s 不存在", name)
	}
	next := map[string]User{}
	for k, v := range u.users {
		if k != name {
			next[k] = v
		}
	}
	return u.save(next)
}

func (u *Users) save(m map[string]User) error {
	list := make([]User, 0, len(m))
	for _, x := range m {
		list = append(list, x)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(u.path), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(u.path, b); err != nil {
		return err
	}
	u.users = m
	if st, err := os.Stat(u.path); err == nil {
		u.mtime, u.size = st.ModTime(), st.Size()
	}
	return nil
}

// 未知用户也跑一次 bcrypt，响应时间不泄露用户是否存在。
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("nfmonitor-dummy-password"), bcryptCost)

// Verify 校验用户名和口令；停用的账号视为失败。
func (u *Users) Verify(name, password string) (User, bool) {
	x, ok := u.Get(name)
	if !ok || x.Disabled || x.Hash == "" {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(x.Hash), []byte(password)) != nil {
		return User{}, false
	}
	return x, true
}

func writeAtomic(path string, b []byte) error {
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
