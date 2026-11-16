#!/usr/bin/env bash
# 在本机构建并打出 deb / rpm 到 dist/。
# 用法: [VERSION=1.2.3] scripts/package.sh
# 二进制链接本机的 glibc 与 webkit2gtk-4.1，只保证能装在与本机同代或更新的发行版上。
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(sed -n 's/^var version = "\(.*\)"$/\1/p' main.go)}"
ARCH="$(go env GOARCH)"
(cd frontend && { [[ -d node_modules ]] || npm install; } && npm run build)
go build -tags desktop,production,webkit2_41 -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o build/bin/nfmonitor .
command -v nfpm >/dev/null || PATH="$(go env GOPATH)/bin:$PATH"
command -v nfpm >/dev/null || go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
mkdir -p dist
sed -e "s|\${VERSION}|${VERSION}|g" -e "s|\${ARCH}|${ARCH}|g" packaging/nfpm.yaml > dist/nfpm.yaml
nfpm package -f dist/nfpm.yaml -p deb -t dist/
nfpm package -f dist/nfpm.yaml -p rpm -t dist/
rm -f dist/nfpm.yaml
ls -la dist/ | grep -E "\.(deb|rpm)$"
