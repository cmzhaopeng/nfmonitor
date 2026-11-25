# nfmonitor

本机与远程主机网络流量与规则的图形化查看工具（Linux）。

把平时要敲 `ip`、`ss`、`nft`、`iptables-save`、`ufw status` 才能拼出来的信息放到一个窗口里：流量从哪块网卡出去、经过哪张路由表、有没有被代理或 TUN 接管、防火墙规则怎么写的、哪个程序在收发数据。

除「防火墙 → ufw 策略 / firewalld 区域」外全部**只读**：不修改任何网卡、路由或防火墙状态。ufw 策略页可以像硬件防火墙的管理界面一样，用表格增删改 ufw 规则、设置默认策略和日志级别；firewalld 区域页可以增删区域里的服务、端口、来源、网卡、rich rule，切换默认区域和地址伪装。每次修改都先显示将要执行的命令，确认后才执行。

在「主机管理」里填好远程主机的地址、SSH 端口、用户和认证方式（口令、私钥或 ssh-agent），就可以在侧栏切换到这台主机，用同样的界面查看它的网卡、路由、连接、防火墙，并修改它的 ufw / firewalld。远程主机上不需要安装任何东西，只需要 sshd 和常见的系统工具。

## 功能

| 页面 | 内容 |
|---|---|
| 总览 | 实时速率、公网出口、应用层代理、防火墙状态，以及一条「本机应用 → 代理 → 策略路由 → 隧道 → 物理出口」的流量路径 |
| 应用 | 按「应用 × 网卡」统计的连接数与流量（TCP，授权后含 UDP） |
| 网卡 | 物理网卡、无线、回环、TUN、网桥等的地址、状态与速率 |
| 路由 | 路由表与策略路由规则（`ip rule`），可输入目标地址测试实际出口 |
| 代理 / TUN | 系统代理设置、监听代理端口的进程、TUN 设备及接管它的规则 |
| 防火墙 | nftables / iptables / ufw / firewalld 规则，按表、链展示，并标出归属（ufw、docker、tailscale、sing-box 等）；可修改 ufw 和 firewalld |
| 连接 | 当前套接字：协议、本地与对端地址、所属进程 |
| 主机管理 | 添加、编辑、测试、删除要监控的远程主机 |

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
nfmonitor dump '/api/links?host=<主机 ID>'   # 远程主机同理（ID 见 ~/.config/nfmonitor/hosts.json）
nfmonitor version
```

## 监控远程主机

1. 打开「主机管理」→「添加主机」，填写 IP 或域名、SSH 端口（默认 22）、用户名。
2. 选择认证方式：
   - **口令**：填写登录口令；
   - **私钥**：填写本机私钥文件路径（如 `~/.ssh/id_ed25519`，配置里只记路径），或直接粘贴私钥内容；私钥有口令保护时填写私钥口令；
   - **ssh-agent**：使用本机 ssh-agent 里的密钥（启动 nfmonitor 的环境里要有 `SSH_AUTH_SOCK`）。
3. 点「获取主机指纹」，与主机上 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` 的输出核对后勾选信任。如果本机 `~/.ssh/known_hosts` 里已有这台主机，会自动比对并提示是否一致。之后每次连接都校验主机密钥，不一致时拒绝连接（防中间人）。
4. 「测试连接」会显示主机名、内核和能否取得 root；然后「保存」。在侧栏顶部的下拉框里切换到这台主机。

**root 权限**：网卡、路由、连接（不含其他用户进程的归属）用普通用户就能看。读取防火墙规则、修改 ufw / firewalld 需要 root，三种方式任选其一：以 root 登录；登录用户配置了免密 sudo；或者在主机设置里填写 sudo 口令（口令认证时默认用登录口令尝试 sudo）。sudo 口令经 SSH 会话的标准输入传给 `sudo -S`，不出现在命令行里。

**远程主机上需要的工具**：`ip`、`ss`（iproute2）、`ps`（procps），读防火墙时按需用到 `nft`、`iptables-save`、`ufw`、`firewall-cmd`。所有命令都以 `LC_ALL=C` 执行，参数逐个按 shell 单引号转义。

**防止把自己锁在外面**：修改远程主机的 ufw / firewalld 前，程序会根据当前 SSH 连接（客户端地址、服务器地址与端口、所在网卡）在内存里模拟修改前后的规则。如果修改后这条连接不再被放行（例如删掉放行 SSH 的规则、在放行规则前插入拒绝规则、启用 ufw 但没有放行 SSH、把 firewalld 的 ssh 服务从当前区域移除），界面会给出红色警告，必须勾选「我知道风险」才能执行；服务端在执行前还会重新读取规则再检查一遍，没带确认的请求一律拒绝。这只是按常见规则做的估计，判断不了的情况（复杂的 iptables 自定义链、端口转发等）不会提示，改动前请确保有控制台等其他恢复途径。

**暂不支持的远程功能**：UDP 流量统计（需要在远程主机上运行 bpftrace 探针）；桌面环境的代理设置（环境变量、GNOME 设置只对本机有意义）；直接编辑 iptables / nftables 规则（与本机一样只读）。

### 凭据如何保存

主机列表保存在 `~/.config/nfmonitor/hosts.json`（遵循 `$XDG_CONFIG_HOME`），目录权限 0700、文件权限 0600。登录口令、粘贴的私钥内容、私钥口令和 sudo 口令以 AES-256-GCM 加密后写入，密钥是同目录下随机生成的 `secret.key`（0600）；每个密文绑定所属主机和字段，不能挪作他用。界面和接口从不回传这些机密，只显示「已保存」。

需要注意：加密密钥和密文在同一台机器、同一个用户目录下，这能防止配置文件被单独拷走、误提交到代码仓库或出现在备份预览里时泄露口令，但**挡不住能读取你家目录的人或程序**。更稳妥的做法是使用私钥文件路径或 ssh-agent，让配置文件里不含任何机密。删除主机会同时删除它保存的机密；要彻底作废，删除 `secret.key` 即可（之后已保存的口令都需要重新填写）。

程序不会把口令写进日志：`NFMONITOR_DEBUG` 只打印请求路径，机密只出现在 POST 请求体里。

## 权限

界面始终以普通用户运行。网卡、路由、代理、套接字这些信息不需要 root。

防火墙规则和按进程的 UDP 流量需要 root。在界面里点「授权」后，程序通过 `pkexec` 启动一个 root 子进程（`nfmonitor helper`），两者经 stdin / stdout 通信。这个子进程：

- 只接受白名单里的命令名，参数是固定的，界面无法让它执行任意命令；
- 白名单里全部是只读命令：`nft -a list ruleset`、`iptables-save`、`ufw status`、读取 `/etc/ufw/user*.rules`、`ss`，以及一个脚本固定的 `bpftrace` 探针；
- 随界面退出而退出。

在「ufw 策略」页确认的修改，也交给这个已授权的子进程执行，不再重复询问密码（与 gufw 授权一次即可管理的体验相同）；还没授权时，则单独用 `pkexec nfmonitor ufw-apply` 起一个一次性的 root 进程（polkit 动作 `org.nfmonitor.ufw`）。修改内容是结构化的 JSON（动作、方向、协议、地址、端口、网卡、备注），由 root 进程重新校验每个字段、对照当前规则确认要改的那条确实存在，再拼成 ufw 参数直接执行（不经过 shell）。只支持增、删、改、调整顺序（拖动或 ↑ ↓；ufw 没有移动命令，实际是删除后在新位置重新插入），启用 / 停用，默认策略和日志级别，不支持 `ufw reset`。

UDP 流量统计靠 `bpftrace` 在 `udp_sendmsg` / `udpv6_sendmsg` / `skb_consume_udp` 上挂 kprobe，只读取内核数据；30 秒没有人查看时探针自动卸载。没有授权或没装 `bpftrace` 时，应用页只统计 TCP。

网页模式只监听回环地址，并校验请求的 Host；修改类接口（授权、ufw / firewalld 修改、主机管理）还要求自定义请求头、JSON 请求体和同源的 Origin，挡住其他网页的跨站请求，并通过 `/proc/net/tcp` 确认连接来自运行本程序的同一用户，本机其他用户无法借它改防火墙。远程主机的数据是用你保存的凭据取来的，所以带 `?host=` 的查询和主机列表也只允许同一用户访问。

远程主机的 root 权限取决于登录用户（root 登录或 sudo），不走本机的 pkexec 授权。

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
- `internal/remote/`：远程主机的配置持久化（机密加密保存）、SSH 连接，以及把远程主机包装成采集层用的 `netinfo.Sys`。
- `internal/api/`：一个 `http.Handler`，桌面窗口与网页模式共用。
- `frontend/`：React + TypeScript + Vite，只通过 `fetch('/api/...')` 取数据。

桌面外壳用的是 [Wails v2](https://wails.io/)。

## 平台

只支持 Linux（本机和被监控的远程主机都是）。采集层依赖 `ip`、`ss`、`/proc`、nftables 等 Linux 专有的接口，目前没有 Windows 和 macOS 的实现。

## 许可证

[MIT](LICENSE)
