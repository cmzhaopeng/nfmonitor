#!/usr/bin/env bash
# 构建服务器版（不含桌面窗口，静态链接，不依赖 webkit / glibc）到 build/bin/nfmonitor-server-linux-<arch>。
# 用法: [VERSION=1.2.3] [GOARCH=amd64|arm64] scripts/build-server.sh
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(sed -n 's/^var version = "\(.*\)"$/\1/p' main.go)}"
ARCH="${GOARCH:-$(go env GOARCH)}"
(cd frontend && { [[ -d node_modules ]] || npm ci; } && npm run build)
mkdir -p build/bin
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
  -o "build/bin/nfmonitor-server-linux-${ARCH}" .
echo "built: build/bin/nfmonitor-server-linux-${ARCH}"
