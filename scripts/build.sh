#!/usr/bin/env bash
# 构建桌面版二进制到 build/bin/nfmonitor（本机 webkit2gtk-4.1）。
set -euo pipefail
cd "$(dirname "$0")/.."
(cd frontend && { [[ -d node_modules ]] || npm install; } && npm run build)
go build -tags desktop,production,webkit2_41 -trimpath -ldflags "-s -w" -o build/bin/nfmonitor .
echo "built: build/bin/nfmonitor"
