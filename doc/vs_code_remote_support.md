# VS Code Remote - SSH 支持指南

本文档说明如何通过 `net_world`（MeshBridge）结合 VS Code **Remote - SSH** 插件，在无需公网 IP、无需传统 VPN，甚至**无需远端安装系统 `sshd`** 的情况下直接进行远程开发。

---

## 一、核心能力架构

VS Code Remote - SSH 连接远端主机时需要以下完整能力：
1. **SSH 命令执行（`exec` / `shell`）**：下发并启动 `~/.vscode-server`。
2. **SSH 本地/远端 TCP 端口转发（`direct-tcpip` / `tcpip-forward`）**：将本地端口通过 SSH 隧道转发至远端 `127.0.0.1:<vscode-server-port>`。
3. **Unix Domain Socket 转发（`direct-streamlocal@openssh.com`）**：支持 VS Code 的 Socket 监听模式（`remote.SSH.remoteServerListenOnSocket`）。
4. **SFTP 子系统与 SSH Agent 转发**：支持文件同步与远端 Git SSH 认证。

`net_world` 在 [ssh_server.go](../ssh_server.go) 中内置了完整支持上述全部协议扩展的 SSH Server（`--ssh-mode=builtin`，默认开启），同时也支持将 22 端口代理至远端系统 OpenSSH `sshd`（`--ssh-mode=local`）。

---

## 二、远端目标机启动（服务端）

### 方式 1：使用内置零依赖 SSH（`--ssh-mode=builtin`，默认推荐）

适用于容器、无 root 权限环境或未启动系统 `sshd` 的机器。

```bash
# 1. 生成服务端持久化密钥（首次执行）
./net_world genkey --key=server

# 2. 指定允许登录的客户端 SSH 公钥并启动网关
./net_world --key=server --ssh-mode=builtin --ssh-authorized-keys=~/.ssh/authorized_keys bridge
```

也可通过 `.env.remote` 文件启动：

```env
TAILCAT_KEY=server
TAILCAT_SSH_MODE=builtin
TAILCAT_SSH_AUTHORIZED_KEYS=~/.ssh/authorized_keys
# 可选：限制允许接入的客户端节点公钥
# TAILCAT_ALLOW_CLIENTS=nodekey:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```bash
./net_world --env-file=.env.remote
```

### 方式 2：代理到远端系统 `sshd`（`--ssh-mode=local`）

如果远端主机已运行系统 OpenSSH `sshd`（`127.0.0.1:22`），可直接代理：

```bash
./net_world --key=server --ssh-mode=local bridge
```

启动后终端会打印当前节点的 `tc` 地址（如 `# 🐈 MeshBridge unified server listening on port 19100 (ssh=builtin): tc...`），复制该 `tc...` 地址即可在本地接入。

---

## 三、本地开发机接入（客户端）

### 方式 A：一键打开 VS Code（`vscode` 子命令，最简方式）

在本地开发机执行以下命令，会自动将主机配置幂等写入 `~/.ssh/config` 并直接唤起 VS Code 连接到远端目录：

```bash
# 语法: ./net_world [flags] vscode [<alias>] [user@]<tc-addr> [remote-path]
./net_world -i ~/.ssh/id_ed25519 vscode my-dev user@<tc-addr> /path/to/workspace
```

---

### 方式 B：一键生成 / 写入 `~/.ssh/config`（`ssh-config` 子命令）

如果希望先写入 `~/.ssh/config`，再从 VS Code 界面手动选择主机连接：

```bash
# 仅预览生成的配置块
./net_world -i ~/.ssh/id_ed25519 ssh-config my-dev user@<tc-addr>

# 自动写入/更新到 ~/.ssh/config（幂等更新 # BEGIN net_world:my-dev 段落）
./net_world -i ~/.ssh/id_ed25519 ssh-config --write my-dev user@<tc-addr>
```

生成的配置块示例：

```sshconfig
# BEGIN net_world:my-dev
Host my-dev
    HostName tailcat-a1b2c3d4e5f60718
    User user
    ProxyCommand '/path/to/net_world' 'connect' '<tc-addr>' '22'
    IdentityFile /Users/admin/.ssh/id_ed25519
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    UpdateHostKeys no
    LogLevel ERROR
    ServerAliveInterval 30
    ServerAliveCountMax 3
# END net_world:my-dev
```

随后打开 VS Code -> `Cmd/Ctrl + Shift + P` -> **Remote-SSH: Connect to Host...** -> 选择 `my-dev`。

---

## 四、常见问题排查

1. **服务端提示 `built-in SSH server disabled (fail-closed): no authorized_keys configured`**
   - `builtin` 模式默认要求配置授权公钥。请通过 `--ssh-authorized-keys=<公钥路径或user@github>`、`TAILCAT_SSH_AUTHORIZED_KEYS` 或 `.mesh/authorized_keys` 提供公钥（仅测试环境可设 `TAILCAT_SSH_ALLOW_UNAUTHENTICATED=1`）。
2. **远端机器无法访问外网下载 `~/.vscode-server`**
   - 在本地 VS Code 设置中开启 `remote.SSH.localServerDownload: "always"`，VS Code 会在本地下载 Server 压缩包并通过内置 SSH/SFTP 通道上传到远端。
3. **更新远端 `tc` 地址**
   - 当远端更换密钥或 `tc` 地址变化时，重新执行一次 `./net_world ssh-config --write my-dev user@<new-tc-addr>` 即可原地更新 `~/.ssh/config` 中对应的 `my-dev` 配置块。
