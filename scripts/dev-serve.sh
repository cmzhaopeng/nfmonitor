#!/usr/bin/env bash
# 重新构建前端 + 二进制，并以网页模式启动（Ctrl-C 结束）。
# 用法: scripts/dev-serve.sh [--fixture]   --fixture: 用 testdata/fixture 里的样例代替 root 数据
set -euo pipefail
cd "$(dirname "$0")/.."
(cd frontend && { [[ -d node_modules ]] || npm install; } && npm run build)
go build -tags desktop,production,webkit2_41 -o build/bin/nfmonitor .
if [[ "${1:-}" == "--fixture" ]]; then export NFMONITOR_FIXTURE_DIR="$PWD/testdata/fixture"; fi
exec ./build/bin/nfmonitor serve -addr "${ADDR:-127.0.0.1:8787}"
