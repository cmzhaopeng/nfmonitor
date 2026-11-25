#!/usr/bin/env bash
# 在 Linux / macOS 上交叉编译 Windows 桌面客户端到 build/bin/nfmonitor.exe（不需要 cgo，也不需要 Windows）。
# 用法: [VERSION=1.2.3] [GOARCH=amd64|arm64] scripts/build-windows.sh
# 运行时需要 Microsoft Edge WebView2 Runtime（Windows 10/11 一般已自带）。
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(sed -n 's/^var version = "\(.*\)"$/\1/p' main.go)}"
ARCH="${GOARCH:-amd64}"
(cd frontend && { [[ -d node_modules ]] || npm ci; } && npm run build)
mkdir -p build/bin
CGO_ENABLED=0 GOOS=windows GOARCH="$ARCH" go build -tags desktop,production -trimpath \
  -ldflags "-s -w -H windowsgui -X main.version=${VERSION}" -o "build/bin/nfmonitor-windows-${ARCH}.exe" .
echo "built: build/bin/nfmonitor-windows-${ARCH}.exe"
