# CLAUDE.md

nfmonitor — 本机网络流量与规则的图形化查看工具（Go + Wails v2 + React/TS/Vite）。
展示网卡、路由 / 策略路由、代理与 TUN、nftables / iptables / ufw 规则、套接字与按进程流量。**只读**，不修改任何系统状态。

## 构建与运行

```bash
scripts/build.sh                 # 前端 + 二进制 → build/bin/nfmonitor
build/bin/nfmonitor              # 桌面窗口
build/bin/nfmonitor serve        # 网页模式，http://127.0.0.1:8787（只允许回环地址）
build/bin/nfmonitor dump /api/links   # 进程内调一次接口，打印 JSON（调试用）
scripts/dev-serve.sh [--fixture] # 重建并以网页模式启动；--fixture 用样例代替 root 数据
go test ./internal/...           # 解析器测试
scripts/package.sh               # deb + rpm → dist/（含 .desktop、图标、polkit 策略）
```

- 本机 `go build` 必须带 `-tags desktop,production,webkit2_41`；`frontend/dist` 是 `go:embed` 的，先构建前端。
- 前端热更新：先跑 `nfmonitor serve`，再 `cd frontend && npm run dev`（vite 把 `/api` 代理到 8787）。
- `NFMONITOR_DEBUG=1`：把每个接口请求打到 stderr。`NFMONITOR_FIXTURE_DIR=<dir>`：从 `<dir>/<命令名>.txt` 读"root 输出"，不提权也能调防火墙界面（样例在 `testdata/fixture/`）。

## 架构

- `internal/netinfo/` 采集层，全部通过解析系统工具输出：`ip -j`（网卡/路由）、`ip rule`、`/proc/net/dev`（速率）、`ss -O -tunapi`（套接字 + TCP 字节数）、`nft -a list ruleset`（文本解析，见 `firewall.go`）、`iptables-save`、`ufw status`。
- `internal/netinfo/apps.go` 按应用统计：`AppTracker` 每 2 秒采样一次套接字（有人查询时才采），把 TCP 字节增量按「应用 × 网卡」累加；网卡由套接字本地地址反查，回环连接会标出对端是本机哪个程序（`lo → gost`）。UDP 没有逐套接字计数，不计流量。
- `internal/priv/` 提权：GUI 始终是普通用户；`pkexec nfmonitor helper` 起一个 root 子进程，经 stdin/stdout 按行 JSON 通信，**只接受 `netinfo.PrivCommands` 白名单里的命令名，参数固定**。新增需要 root 的命令只能往这个表里加只读命令。安装包带的 polkit 策略（`packaging/org.nfmonitor.helper.policy`）只匹配 `/usr/bin/nfmonitor helper`。
- `internal/api/` 一个 `http.Handler`，桌面版挂在 Wails `AssetServer.Handler` 上，`serve` 模式挂在普通 HTTP 服务上——前端在两种模式下都只用 `fetch('/api/...')`，没有 Wails 绑定。
- `frontend/src/`：`api.ts`（类型 + `usePoll`）、`rates.tsx`（每秒采样算速率，全局 context）、`pages/*`（七个页面）。

## 约定

- iptables 是 nf_tables 后端时，iptables / ufw / docker 的规则都在 nft ruleset 里，统一用 `FwTable/FwChain/FwRule` 模型；legacy 后端由 `ParseIptablesSave` 转成同一模型。
- 链的"归属"（ufw / docker / tailscale / sing-box …）靠表名、链名前缀猜，见 `ownerOf`。
- 状态一律「色点 + 文字」；图表配色：下行蓝、上行橙，定义在 `styles.css` 的 CSS 变量里（含深色模式）。
- 改完界面要在浏览器里实际看一遍（Chrome 调试口 9222 可用）。
