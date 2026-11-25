# CLAUDE.md

nfmonitor — 本机网络流量与规则的图形化查看工具（Go + Wails v2 + React/TS/Vite）。
展示网卡、路由 / 策略路由、代理与 TUN、nftables / iptables / ufw 规则、套接字与按进程流量。除 ufw 策略页外**只读**，不修改任何系统状态；ufw 修改只经结构化的 `UfwOp`、在 root 侧校验（见下）。

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
- `internal/netinfo/apps.go` 按应用统计：`AppTracker` 每 2 秒采样一次套接字（有人查询时才采），把 TCP 字节增量按「应用 × 网卡」累加；网卡由套接字本地地址反查，回环连接会标出对端是本机哪个程序（`lo → gost`）。UDP 没有逐套接字计数：授权后由 helper 常驻一个 `bpftrace` 探针（`udp.go`，kprobe `udp_sendmsg` / `udpv6_sendmsg` / `skb_consume_udp`，脚本固定），每秒按「进程 × 端口 × 网卡」输出载荷字节增量，`AppTracker` 经白名单命令 `udpstat` 取走并累加；30 秒没人取数探针自动退出。未授权或没装 bpftrace 时只有 TCP。
- `internal/priv/` 提权：GUI 始终是普通用户；`pkexec nfmonitor helper` 起一个 root 子进程，经 stdin/stdout 按行 JSON 通信，**只接受 `netinfo.PrivCommands` 白名单里的命令名，参数固定**（新增需要 root 的命令只能往这个表里加只读命令），外加一种 `{"ufw": UfwOp}` 请求，由 `netinfo.ApplyUfw` 在 root 侧校验后执行。安装包带的 polkit 策略（`packaging/org.nfmonitor.helper.policy`）只匹配 `/usr/bin/nfmonitor helper`。
- `internal/netinfo/ufw.go` ufw 策略：规则读自 `/etc/ufw/user*.rules` 的 `### tuple ###` 行（helper 的 `ufw-tuples`，ufw 停用时也有），默认策略 / 日志读全员可读的 `/etc/default/ufw`、`/etc/ufw/ufw.conf`。写操作是结构化的 `UfwOp`，经 `POST /api/ufw/preview`（只生成命令）和 `/api/ufw/apply`；apply 优先交给已授权的常驻 helper（不再弹密码）；helper 没起时 `pkexec nfmonitor ufw-apply`（polkit 动作 `org.nfmonitor.ufw`）起一次性 root 进程。两条路都走 `ApplyUfw`：**在 root 侧重新校验并对照当前规则**后用 argv 执行 ufw。serve 模式下修改类接口经 `peerUID`（`/proc/net/tcp`）要求连接与本程序同一用户。开发版（build/bin）的路径不匹配 polkit 策略，pkexec 会退回通用动作、每次都要密码。ufw 的 `--force` 只能放最前面且会让裸 `allow` 不被识别成规则，所以只给 delete 加；生成的命令可以拿 ufw 自带的 Python 解析器（`ufw.frontend.parse_command`）离线校验。调整顺序（`move`，`planMove`）= 先按 spec 删除，再把 v4、v6 两份分别用显式 `0.0.0.0/0` / `::/0` 插回各自表里的位置（两张表序号分开、优先级只在同方向同版本内有意义），步骤在内存里模拟算序号；插入失败会把原规则追加回末尾。
- `internal/api/` 一个 `http.Handler`，桌面版挂在 Wails `AssetServer.Handler` 上，`serve` 模式挂在普通 HTTP 服务上——前端在两种模式下都只用 `fetch('/api/...')`，没有 Wails 绑定。
- `frontend/src/`：`api.ts`（类型 + `usePoll`）、`rates.tsx`（每秒采样算速率，全局 context）、`pages/*`（七个页面）。

## 约定

- iptables 是 nf_tables 后端时，iptables / ufw / docker 的规则都在 nft ruleset 里，统一用 `FwTable/FwChain/FwRule` 模型；legacy 后端由 `ParseIptablesSave` 转成同一模型。
- 链的"归属"（ufw / docker / tailscale / sing-box …）靠表名、链名前缀猜，见 `ownerOf`。
- 等宽字体只写 `monospace`：桌面版 WebKitGTK 会把字体列表里第一个没安装的名字（`ui-monospace`、`JetBrains Mono`…）交给 fontconfig，拿回 Noto Sans CJK 这类比例字体就直接用，原始输出对不齐（Chrome 里看不出来）。
- 状态一律「色点 + 文字」；图表配色：下行蓝、上行橙，定义在 `styles.css` 的 CSS 变量里（含深色模式）。
- 改完界面要在浏览器里实际看一遍（Chrome 调试口 9222 可用）。
