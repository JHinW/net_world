# net_world (MeshBridge)

基于 [tailcat](https://github.com/tailscale/tailcat) 构建的轻量级点对点 Mesh 网关与命令行工具，提供单进程入站/出站多路复用、端口转发、SSH 接入与自定义 `.env` 配置文件启动能力。

## 环境要求

- **Go >= 1.27.1**（由 [go.mod](go.mod) 及 `github.com/tailscale/tailcat@v0.7.0` 要求）

## 快速开始

### 1. 编译与测试

```bash
# 编译二进制
go build -o net_world .

# 运行单元测试
go test -v ./...
```

### 2. 从自定义配置文件启动

```bash
# 复制环境变量模板并按需修改
cp .env.example .env.custom

# 使用自定义环境文件启动网关（默认监听 19100 + SSH 22）
./net_world --env-file=.env.custom

# 也可通过环境变量指定配置文件
TAILCAT_ENV_FILE=.env.custom ./net_world
```

> 命令行参数优先级高于环境变量与 `.env` 文件中的配置，可用于临时覆盖（例如 `./net_world --env-file=.env.custom --verbose bridge 29100`）。

### 3. 直接启动（无配置文件）

```bash
# 默认等价于 `bridge 19100`
./net_world

# 查看帮助
./net_world --help
```

## 子命令说明

| 子命令 | 用法 | 说明 |
| :--- | :--- | :--- |
| `bridge`（默认） | `net_world [flags] [bridge [port]]` | 启动统一单进程网关：后台启动入站服务（默认 `19100` + SSH `22`），并在 `stdin/stdout` 运行出站多路复用器 |
| `ssh` | `net_world [flags] ssh [-p <port>] [user@]<tc-addr> [command [args...]]` | 通过 Tailcat 连接目标节点 SSH（默认端口 `22`） |
| `ssh-config` | `net_world [flags] ssh-config [--write] [<alias>] [user@]<tc-addr>` | 生成 VS Code Remote - SSH / OpenSSH 所需的 `Host` 配置块，支持 `--write` 幂等写入 `~/.ssh/config` |
| `vscode` | `net_world [flags] vscode [<alias>] [user@]<tc-addr> [remote-path]` | 自动配置 `~/.ssh/config` 并直接拉起本地 VS Code 连接远端主机与目录 |
| `connect` | `net_world [flags] connect <tc-addr> [port\|ip:port]` | 将 `stdin/stdout` 透传到目标节点指定端口（默认 `22`）；支持简写 `net_world <tc-addr> [port]` |
| `forward` | `net_world [flags] forward [--bind=127.0.0.1] <tc-addr> <[local:]remote-port> [...]` | 将远端节点端口转发到本地 TCP 端口 |
| `genkey` | `net_world [flags] genkey [--client] [--fixed-region] [--force]` | 生成服务端密钥（输出 `tc...` 地址）或客户端密钥（`--client`，输出 `nodekey:...`） |
| `parse` | `net_world [flags] parse <tc-addr>` | 解析 `tc` 地址并输出 JSON 元信息 |
| `version` | `net_world version` / `--version` | 输出版本信息（`v0.7.0-mesh-bridge`） |

## 命令行参数（Flags）

| 参数 | 说明 |
| :--- | :--- |
| `--env-file=<path>` | 从自定义 `.env` 文件加载环境变量 |
| `--key=<path\|name>` | 服务端密钥路径或名称（未指定 `--client-key` 时也作为客户端密钥回退） |
| `--client-key=<path\|name>` | 客户端身份密钥路径或名称 |
| `--addr-file=<path\|tcp:host:port>` | 将活跃服务端 `tc` 地址写入本地文件或发送到指定 TCP 端点 |
| `--serve-ports=<ports\|range\|all>` | 额外暴露的本地 TCP 端口（支持逗号分隔、端口范围如 `8000-8010` 或 `all`） |
| `--ssh-mode=<builtin\|local\|off>` | 入站 22 端口的 SSH 服务模式（默认：`builtin`） |
| `--ssh-authorized-keys=<sources>` | 允许的 SSH 公钥来源（逗号分隔的 `authorized_keys` 路径、公钥字符串或 `user@github`） |
| `--allow=<nodekeys>` | 允许接入的客户端节点公钥白名单（逗号分隔的 `nodekey:...`） |
| `--derpmap-url=<url>` | 自定义 DERP Map URL |
| `--bind=<ip>` | `forward` 子命令的本地绑定 IP（默认：`127.0.0.1`） |
| `-p, --port=<port\|ip:port>` | `ssh` / `ssh-config` / `vscode` 子命令的目标端口（默认：`22`） |
| `-i, --identity=<ssh-private-key>` | `ssh` / `ssh-config` / `vscode` 子命令使用的私钥路径（默认自动探测 `.mesh/ssh_id_ed25519`） |
| `-w, --write` | `ssh-config` 子命令：将生成的 `Host` 配置块幂等写入 `~/.ssh/config` |
| `--ssh-config=<path>` | `ssh-config` / `vscode` 子命令：自定义 SSH 配置文件路径（默认：`~/.ssh/config`） |
| `-v, --verbose` | 输出详细运行日志 |
| `--client` / `--fixed-region` / `-f, --force` | `genkey` 子命令选项 |

## 环境变量

完整示例与注释见 [`.env.example`](.env.example)：

| 变量名 | 对应参数 / 说明 |
| :--- | :--- |
| `TAILCAT_ENV_FILE` | 同 `--env-file` |
| `TAILCAT_BRIDGE_PORT` | `bridge` 默认监听端口（默认 `19100`） |
| `TAILCAT_KEY` | 同 `--key` |
| `TAILCAT_CLIENT_KEY` | 同 `--client-key` |
| `TAILCAT_VERBOSE` | 设为 `1` 或 `true` 等价于 `-v/--verbose` |
| `TAILCAT_DERPMAP_URL` | 同 `--derpmap-url` |
| `TAILCAT_ADDR_FILE` | 同 `--addr-file` |
| `TAILCAT_SERVE_PORTS` | 同 `--serve-ports` |
| `TAILCAT_ALLOW_CLIENTS` | 同 `--allow` |
| `TAILCAT_SSH_MODE` | 同 `--ssh-mode`（默认 `builtin`） |
| `TAILCAT_SSH_AUTHORIZED_KEYS` | 同 `--ssh-authorized-keys` |
| `TAILCAT_SSH_ALLOW_UNAUTHENTICATED` | 仅 `builtin` SSH 模式有效：未配置公钥时设为 `1` 允许无认证接入 |
| `TAILCAT_SSH_IDENTITY_FILE` | 同 `-i, --identity` |

## 项目结构

```text
.
├── main.go             # CLI 入口、参数解析与 BridgeApp 编排
├── inbound.go          # InboundGateway：入站网关、端口暴露与 SSH 服务
├── ssh_server.go       # 内置零依赖 SSH Server（支持 VS Code 端口转发、Unix Socket 转发与 SFTP）
├── ssh_pty_unix.go     # Unix/macOS PTY 终端与会话环境实现
├── ssh_pty_windows.go  # Windows 会话环境实现
├── outbound.go         # OutboundMultiplexer：基于 stdin/stdout 的出站多路复用器
├── client.go           # StandaloneClient：ssh / ssh-config / vscode / connect / forward 客户端实现
├── identity.go         # IdentityVault：服务端/客户端密钥、SSH 私钥与地址解析
├── envfile.go          # 自定义 .env 文件解析器
├── bridge_test.go      # 单元测试
├── doc/                # 专题文档（含 VS Code Remote - SSH 支持指南）
├── .env.example        # 环境变量配置模板
├── go.mod / go.sum     # Go 模块依赖定义
└── .gitignore
```
