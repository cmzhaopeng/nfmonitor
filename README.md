# nfmonitor

本机与远程主机网络流量与规则的图形化查看工具。有三种用法：

- **Linux 桌面版**：看本机，也能经 SSH 看远程 Linux 主机；
- **Windows 客户端**：作为管理端，经 SSH 监控远程 Linux 主机、修改它们的防火墙（Windows 本机不采集）；
- **服务器版**（`nfmonitor server`）：部署在一台服务器上，浏览器登录后集中监控所有纳管主机的网络和安全策略，带账号权限和审计日志。

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
| 所有主机 | 所有纳管主机一屏看完：在线状态、流量、连接与对外监听端口、防火墙状态，以及需要注意的问题（没开防火墙、入站默认放行、对外暴露数据库 / 远程桌面等端口、拿不到 root） |
| 审计日志 | 服务器版：谁、何时、从哪个 IP、对哪台主机做了什么（仅管理员可见） |

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

### Windows 客户端

```bash
scripts/build-windows.sh                 # 在 Linux / macOS 上交叉编译 → build/bin/nfmonitor-windows-amd64.exe
GOARCH=arm64 scripts/build-windows.sh    # ARM 版
```

不需要 cgo，也不需要 Windows 机器。每次推送到 GitHub 时，Actions（`.github/workflows/build.yml`）也会构建好 exe，在该次运行的 Artifacts 里下载 `nfmonitor-windows`。

运行需要 Microsoft Edge WebView2 Runtime（Windows 10 / 11 一般已自带，没有时到微软官网下载安装）。双击 `nfmonitor-windows-amd64.exe` 打开窗口，在「主机管理」里添加远程 Linux 主机即可，用法与 Linux 版的远程监控相同。Windows 版没有「本机」：本机的网卡、路由、防火墙采集依赖 Linux 工具，在 Windows 上不提供。主机配置保存在 `%AppData%\nfmonitor\hosts.json`，机密的加密方式与 Linux 版相同（见下文「凭据如何保存」）。exe 还没有程序图标和数字签名，首次运行时 SmartScreen 可能提示「未知发布者」。

## 使用

```bash
nfmonitor                              # 打开桌面窗口
nfmonitor serve                        # 网页模式，http://127.0.0.1:8787
nfmonitor serve -addr 127.0.0.1:9000   # 换端口（只允许回环地址）
nfmonitor server -h                    # 服务器版，见下文「服务器版」
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

## 服务器版

`nfmonitor server` 把同一套界面作为网站提供：部署在一台能 SSH 到各主机的服务器上，管理员在浏览器里纳管主机，所有人登录后在「所有主机」页看整体情况，点进某台主机看它的网卡、路由、连接和防火墙。服务器自己的网络不在监控范围内（没有「本机」），要监控它就把它也作为一台主机添加进来。

### 安全设计

- **登录**：账号口令用 bcrypt 保存在 `<数据目录>/users.json`，口令至少 10 个字符。同一来源 IP 15 分钟内失败 20 次封 15 分钟；同一账号连续失败 5 次起锁定 1、2、4 … 分钟（最长 1 小时）。会话 30 分钟无操作或登录满 12 小时失效，改口令 / 停用账号会让该账号已登录的会话立即失效。
- **两种角色**：`admin` 可以纳管主机、修改防火墙；`viewer` 只能看（服务端拒绝所有修改请求，界面也隐藏修改按钮）。
- **危险操作要再次输入口令**：保存 / 删除主机、执行 ufw / firewalld 修改前，若距上次输入口令超过 5 分钟，会弹框要求重新输入。修改远程防火墙前照常做防失联检查。
- **主密钥与密文分开存放**：主机的 SSH 口令、私钥等用 AES-256-GCM 加密保存在 `<数据目录>/hosts.json`，密钥必须从外部提供（`-key-file`、环境变量 `NFMONITOR_MASTER_KEY_FILE` 或 `NFMONITOR_MASTER_KEY`），放在数据目录里会拒绝启动。只拷走数据目录（例如备份泄露）拿不到任何口令。用错密钥时拒绝启动，不会覆盖已有的机密。服务器版只接受口令或粘贴的私钥内容，不读服务器上的私钥文件，也不用 ssh-agent。
- **审计日志**：登录（含失败）、退出、纳管主机的增删改与连接、每次防火墙修改（含实际执行的命令和结果）、被拒绝的操作都记入 `<数据目录>/audit.log`（每行一条 JSON，超过 20 MB 轮转，保留 5 份），同时输出到服务日志（journald / docker logs）。日志里不含任何口令或私钥。管理员可在「审计日志」页查看。
- **HTTPS**：监听非回环地址时必须启用 HTTPS（`-tls-cert` / `-tls-key`），或放在做 HTTPS 的反向代理后面并加 `-behind-proxy`，否则拒绝启动。会话 cookie 为 `HttpOnly`、`SameSite=Strict`，HTTPS 下为 `Secure` 的 `__Host-` cookie。修改类请求要求同源 Origin、自定义请求头和 JSON 请求体，防跨站请求；页面带 CSP、`X-Frame-Options` 等安全头。
- 服务器版不提供「授权」（pkexec）和本机采集，也不能在服务器本机执行任何命令；对各主机的操作都经 SSH，权限取决于你给的账号。

### 快速开始（单个二进制）

```bash
scripts/build-server.sh            # → build/bin/nfmonitor-server-linux-amd64（静态链接，不依赖 GTK / WebKit）
B=build/bin/nfmonitor-server-linux-amd64

sudo install -d -m700 /etc/nfmonitor
$B server genkey | sudo tee /etc/nfmonitor/master.key >/dev/null && sudo chmod 400 /etc/nfmonitor/master.key
$B server user add admin -role admin -data /var/lib/nfmonitor     # 从终端读口令，不回显
$B server -data /var/lib/nfmonitor -key-file /etc/nfmonitor/master.key   # http://127.0.0.1:8787
```

只监听本机时可以经 SSH 端口转发访问：`ssh -L 8787:127.0.0.1:8787 服务器`，再打开 http://127.0.0.1:8787 。

**务必备份主密钥**（与数据目录分开存放）。丢了密钥，`hosts.json` 里保存的口令都无法解开，只能逐台重新填写。

### 部署方式一：systemd + nginx

```bash
sudo install -m755 build/bin/nfmonitor-server-linux-amd64 /usr/local/bin/nfmonitor
sudo useradd --system --home-dir /var/lib/nfmonitor --shell /usr/sbin/nologin nfmonitor
sudo install -d -m700 /etc/nfmonitor
nfmonitor server genkey | sudo tee /etc/nfmonitor/master.key >/dev/null && sudo chmod 400 /etc/nfmonitor/master.key
sudo install -d -m700 -o nfmonitor -g nfmonitor /var/lib/nfmonitor
sudo -u nfmonitor nfmonitor server user add admin -role admin -data /var/lib/nfmonitor
sudo install -m644 packaging/nfmonitor-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now nfmonitor-server
journalctl -u nfmonitor-server -f       # 服务日志 + 审计记录
```

单元文件（`packaging/nfmonitor-server.service`）用 systemd 的 `LoadCredential` 把主密钥只读地交给服务（服务用户本身不能读 `/etc/nfmonitor`），并做了常见的加固（`ProtectSystem=strict`、`NoNewPrivileges` 等）。服务只监听 `127.0.0.1:8787`，由 nginx 做 HTTPS：参考 `packaging/nginx-nfmonitor.conf`，换成你的域名和证书。如果访问用的域名与 nginx 传给后端的 Host 不一致，加 `-allowed-origins https://你的域名`。

### 部署方式二：Docker

```bash
docker build -t nfmonitor .
mkdir -p secrets && docker run --rm nfmonitor genkey > secrets/master.key
sudo chown 65532:65532 secrets/master.key && sudo chmod 400 secrets/master.key   # 容器内的用户是 65532
docker compose run --rm -it nfmonitor user add admin -role admin
docker compose up -d
```

`docker-compose.yml` 把数据放在卷 `nfmonitor-data`，主密钥以 Docker secret 挂进容器（不在卷里），端口只绑定宿主机的 `127.0.0.1:8787`，同样由宿主机上的 nginx / Caddy 做 HTTPS。镜像基于 distroless，以非 root 用户运行，根文件系统只读。

### 账号管理

在服务器上用命令行管理（服务运行中修改也立即生效）：

```bash
nfmonitor server user add <名字> [-role admin|viewer]   # 默认 viewer
nfmonitor server user passwd <名字>                     # 改口令（该账号已登录的会话失效）
nfmonitor server user role <名字> admin|viewer
nfmonitor server user disable|enable <名字>
nfmonitor server user del <名字>
nfmonitor server user list
```

都要带 `-data <数据目录>`（或设置 `NFMONITOR_DATA`）；脚本里可加 `-password-stdin` 从标准输入读口令。

### 启动参数

| 参数 | 说明 |
|---|---|
| `-addr` | 监听地址，默认 `127.0.0.1:8787` |
| `-data` | 数据目录，默认 `$NFMONITOR_DATA` 或 `/var/lib/nfmonitor`（Windows 为 `%ProgramData%\nfmonitor`） |
| `-key-file` | 主密钥文件（32 字节，原始 / base64 / hex 均可）；也可用 `NFMONITOR_MASTER_KEY_FILE`、`NFMONITOR_MASTER_KEY` |
| `-tls-cert` / `-tls-key` | 直接提供 HTTPS |
| `-behind-proxy` | 前面有 HTTPS 反向代理；客户端 IP 取自 `X-Forwarded-For`（只信任 `-trusted-proxies` 里的代理，默认本机） |
| `-allowed-origins` | 额外接受的 Origin，逗号分隔；也可用 `NFMONITOR_ALLOWED_ORIGINS` |
| `-session-idle` / `-session-max` | 会话空闲超时（默认 30m）/ 最长有效期（默认 12h） |

建议再在防火墙或 nginx 上限制只有办公网 / VPN 能访问这个网站：它握有所有纳管主机的 SSH 凭据。

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

`testdata/` 里只放虚构数据（IP 用 192.0.2.0/24 这类文档地址）。要拿本机真实输出调试，放到仓库里的 `local/` 目录（已在 `.gitignore` 里，不会被提交），例如 `NFMONITOR_FIXTURE_DIR=$PWD/local/fixture`。主机清单、密钥、证书、`.env` 等也已在 `.gitignore` 里忽略。

### 结构

- `internal/netinfo/`：采集层，全部通过解析系统工具的输出实现。
- `internal/priv/`：提权与 helper 通信。
- `internal/remote/`：远程主机的配置持久化（机密加密保存）、SSH 连接，以及把远程主机包装成采集层用的 `netinfo.Sys`。
- `internal/api/`：一个 `http.Handler`，桌面窗口、网页模式和服务器版共用；`fleet.go` 是「所有主机」的汇总。
- `internal/server/`：服务器版：账号、会话、登录限速、权限与再次验证、审计日志、外部主密钥，包在 `internal/api` 外面。
- `frontend/`：React + TypeScript + Vite，只通过 `fetch('/api/...')` 取数据。

桌面外壳用的是 [Wails v2](https://wails.io/)。

## 平台

被监控的主机只支持 Linux：采集层依赖 `ip`、`ss`、`/proc`、nftables 等 Linux 专有的接口。管理端可以是 Linux 桌面版、Windows 客户端（只监控远程主机）或服务器版（浏览器访问）。macOS 没有测试过。

## 许可证

[MIT](LICENSE)
