package server

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"nfmonitor/internal/remote"
)

// 服务器版的主密钥：加密主机口令 / 私钥的 AES-256 密钥。它必须和数据目录分开存放，
// 这样数据目录（备份、快照、被拷走的卷）单独泄露时，里面的密文解不开。
//
// 来源（按顺序取第一个）：
//  1. -key-file 参数
//  2. 环境变量 NFMONITOR_MASTER_KEY_FILE（适合 systemd LoadCredential / Docker secrets）
//  3. 环境变量 NFMONITOR_MASTER_KEY（base64 或 hex）
//
// 文件内容可以是 32 字节原始数据，或 base64 / hex 文本。用 `nfmonitor server genkey` 生成。

const (
	envKey     = "NFMONITOR_MASTER_KEY"
	envKeyFile = "NFMONITOR_MASTER_KEY_FILE"
)

// LoadKey 按上面的顺序读取主密钥。dataDir 用来拒绝放在数据目录里的密钥文件。
func LoadKey(keyFile, dataDir string) ([]byte, string, error) {
	if keyFile == "" {
		keyFile = os.Getenv(envKeyFile)
	}
	if keyFile != "" {
		abs, err := filepath.Abs(keyFile)
		if err != nil {
			return nil, "", err
		}
		if inside(abs, dataDir) {
			return nil, "", fmt.Errorf("密钥文件 %s 在数据目录 %s 里：密钥要和密文分开存放（例如 /etc/nfmonitor/master.key 或 systemd / Docker 的 secret）", abs, dataDir)
		}
		st, err := os.Stat(abs)
		if err != nil {
			return nil, "", fmt.Errorf("读取密钥文件: %w", err)
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0o007 != 0 {
			log.Printf("警告：密钥文件 %s 其他用户可读（%v），建议 chmod 600 / 400", abs, st.Mode().Perm())
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			return nil, "", fmt.Errorf("读取密钥文件: %w", err)
		}
		k, err := decodeKey(b)
		if err != nil {
			return nil, "", fmt.Errorf("密钥文件 %s: %w", abs, err)
		}
		return k, "文件 " + abs, nil
	}
	if v := os.Getenv(envKey); v != "" {
		os.Unsetenv(envKey) // 不留在环境里
		k, err := decodeKey([]byte(v))
		if err != nil {
			return nil, "", fmt.Errorf("环境变量 %s: %w", envKey, err)
		}
		return k, "环境变量 " + envKey, nil
	}
	return nil, "", errors.New("没有主密钥：用 `nfmonitor server genkey > /etc/nfmonitor/master.key` 生成，再用 -key-file、" +
		envKeyFile + " 或 " + envKey + " 提供（不要放在数据目录里）")
}

func decodeKey(b []byte) ([]byte, error) {
	if len(b) == remote.KeySize {
		return b, nil
	}
	s := strings.TrimSpace(string(b))
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString, base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString, base64.RawURLEncoding.DecodeString, hex.DecodeString,
	} {
		if k, err := dec(s); err == nil && len(k) == remote.KeySize {
			return k, nil
		}
	}
	return nil, fmt.Errorf("应为 %d 字节的密钥（base64 或 hex 文本）", remote.KeySize)
}

func inside(path, dir string) bool {
	d, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(d, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
