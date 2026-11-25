# nfmonitor

本机网络流量与规则的图形化查看工具（Linux）。

把平时要敲 `ip`、`ss`、`nft`、`iptables-save`、`ufw status` 才能拼出来的信息放到一个窗口里：流量从哪块网卡出去、经过哪张路由表、有没有被代理或 TUN 接管、防火墙规则怎么写的、哪个程序在收发数据。

除「防火墙 → ufw 策略」外全部**只读**：不修改任何网卡、路由或防火墙状态。ufw 策略页可以像硬件防火墙的管理界面一样，用表格增删改 ufw 规则、设置默认策略和日志级别，每次修改都先显示将要执行的 ufw 命令，确认后才执行。

## 功能

| 页面 | 内容 |
|---|---|
| 总览 | 实时速率、公网出口、应用层代理、防火墙状态，以及一条「本机应用 → 代理 → 策略路由 → 隧道 → 物理出口」的流量路径 |
| 应用 | 按「应用 × 网卡」统计的连接数与流量（TCP，授权后含 UDP） |
| 网卡 | 物理网卡、无线、回环、TUN、网桥等的地址、状态与速率 |
| 路由 | 路由表与策略路由规则（`ip rule`），可输入目标地址测试实际出口 |
| 代理 / TUN | 系统代理设置、监听代理端口的进程、TUN 设备及接管它的规则 |
| 防火墙 | nftables / iptables / ufw 规则，按表、链展示，并标出归属（ufw、docker、tailscale、sing-box 等） |
| 连接 | 当前套接字：协议、本地与对端地址、所属进程 |

## 安装

需要 Linux、GTK 3 和 WebKit2GTK 4.1。目前没有预编译的发布包，请从源码构建。

### 打包安装（推荐）

```bash
scripts/package.sh        # 生成 deb 和 rpm 到 dist/
sudo dnf install ./dist/nfmonitor-*.rpm     # Fedora / RHEL 系
sudo apt install ./dist/nfmonitor_*.deb     # Debian / Ubuntu 系
```

安装包含 `/usr/bin/nfmonitor`、应用菜单图标和 polkit 策略。`nftables`、`iptables`、`polkit`、`bpftrace` 是推荐依赖，缺少时对应功能不可用，其余照常工作。

二进制链接的是构建机上的 glibc 与 WebKit2GTK，只保证能装在与构建机同代或更新的发行版上。

### 只构建二进制

```bash
scripts/build.sh          # 前端 + 二进制 → build/bin/nfmonitor
```

构建需要 Go（版本见 `go.mod`）、Node.js 和 npm，以及 GTK 3 / WebKit2GTK 4.1 的开发包。

## 使用

```bash
nfmonitor                              # 打开桌面窗口
nfmonitor serve                        # 网页模式，http://127.0.0.1:8787
nfmonitor serve -addr 127.0.0.1:9000   # 换端口（只允许回环地址）
nfmonitor dump /api/links              # 调一次接口并打印 JSON，调试用
nfmonitor version
```

## 权限

界面始终以普通用户运行。网卡、路由、代理、套接字这些信息不需要 root。

防火墙规则和按进程的 UDP 流量需要 root。在界面里点「授权」后，程序通过 `pkexec` 启动一个 root 子进程（`nfmonitor helper`），两者经 stdin / stdout 通信。这个子进程：

- 只接受白名单里的命令名，参数是固定的，界面无法让它执行任意命令；
- 白名单里全部是只读命令：`nft -a list ruleset`、`iptables-save`、`ufw status`、读取 `/etc/ufw/user*.rules`、`ss`，以及一个脚本固定的 `bpftrace` 探针；
- 随界面退出而退出。

修改 ufw 不经过这个只读子进程。每次修改单独用 `pkexec nfmonitor ufw-apply` 起一个一次性的 root 进程（独立的 polkit 动作 `org.nfmonitor.ufw`），修改内容是结构化的 JSON（动作、方向、协议、地址、端口、网卡、备注），由 root 进程重新校验每个字段、对照当前规则确认要改的那条确实存在，再拼成 ufw 参数直接执行（不经过 shell）。只支持增、删、改规则，启用 / 停用，默认策略和日志级别，不支持 `ufw reset`。

UDP 流量统计靠 `bpftrace` 在 `udp_sendmsg` / `udpv6_sendmsg` / `skb_consume_udp` 上挂 kprobe，只读取内核数据；30 秒没有人查看时探针自动卸载。没有授权或没装 `bpftrace` 时，应用页只统计 TCP。

网页模式只监听回环地址，并校验请求的 Host；修改类接口还要求自定义请求头、JSON 请求体和同源的 Origin，挡住其他网页的跨站请求。

## 开发

```bash
go test ./internal/...            # 解析器测试
scripts/dev-serve.sh              # 重建并以网页模式启动
scripts/dev-serve.sh --fixture    # 用 testdata/fixture/ 里的样例代替 root 数据
```

前端热更新：先运行 `nfmonitor serve`，再执行 `cd frontend && npm run dev`，vite 会把 `/api` 代理到 8787 端口。

环境变量：

- `NFMONITOR_DEBUG=1`：把每个接口请求打印到 stderr。
- `NFMONITOR_FIXTURE_DIR=<目录>`：从 `<目录>/<命令名>.txt` 读取「root 输出」，不提权也能调试防火墙界面。

### 结构

- `internal/netinfo/`：采集层，全部通过解析系统工具的输出实现。
- `internal/priv/`：提权与 helper 通信。
- `internal/api/`：一个 `http.Handler`，桌面窗口与网页模式共用。
- `frontend/`：React + TypeScript + Vite，只通过 `fetch('/api/...')` 取数据。

桌面外壳用的是 [Wails v2](https://wails.io/)。

## 平台

只支持 Linux。采集层依赖 `ip`、`ss`、`/proc`、nftables 等 Linux 专有的接口，目前没有 Windows 和 macOS 的实现。

## 许可证

[MIT](LICENSE)
