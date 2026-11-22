# VS Code Remote - SSH Usage Tutorial (`net_world`) / VS Code Remote - SSH 使用教程

This tutorial explains how to deploy `net_world` on a remote Linux host and connect to it from VS Code **Remote - SSH** without a public IP or system `sshd`.  
本教程介绍如何在远端 Linux 主机部署 `net_world`，并通过 VS Code **Remote - SSH** 插件直接进行远程开发（无需公网 IP，也无需远端安装系统 `sshd`）。

---

## 1. Prerequisites / 前置条件

- **Local machine / 本地开发机**:
  - `net_world` binary (built with Go >= 1.27.1). / `net_world` 可执行文件（需 Go >= 1.27.1 编译）。
  - VS Code with the **Remote - SSH** extension (`ms-vscode-remote.remote-ssh`). / 已安装 **Remote - SSH** 插件的 VS Code。
  - An SSH key pair (e.g., `~/.ssh/id_ed25519` and `~/.ssh/id_ed25519.pub`). / 一对 SSH 密钥（如 `~/.ssh/id_ed25519` 与 `~/.ssh/id_ed25519.pub`）。
- **Remote machine / 远端目标机**:
  - Outbound HTTPS/UDP access to Tailscale DERP relays. / 可出站访问 Tailscale DERP 中继节点。

---

## 2. Remote Machine Setup (Server) / 远端机器部署（服务端）

### Step 1: Build & Upload Binary / 第一步：编译并上传二进制

If the remote machine (`linux/amd64`) does not have Go >= 1.27.1 installed, cross-compile locally and upload:  
若远端机器（`linux/amd64`）未安装 Go >= 1.27.1，可在本地交叉编译后上传：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o net_world-linux-amd64 .
scp net_world-linux-amd64 <user>@<remote-host>:~/net_world/net_world
```

### Step 2: Generate Persistent Server Key / 第二步：生成持久化服务端密钥

On the remote machine / 在远端机器上执行：

```bash
mkdir -p ~/net_world && cd ~/net_world
chmod +x net_world
./net_world genkey --key=server
```

### Step 3: Authorize Your SSH Public Key / 第三步：配置 SSH 授权公钥

Ensure your local public key is in `~/.ssh/authorized_keys` on the remote machine:  
确保本地公钥已写入远端机器的 `~/.ssh/authorized_keys`：

```bash
cat ~/.ssh/id_ed25519.pub | ssh <user>@<remote-host> 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
```

### Step 4: Create `.env.remote` / 第四步：创建 `.env.remote` 配置文件

```env
TAILCAT_KEY=server
TAILCAT_SSH_MODE=builtin
TAILCAT_SSH_AUTHORIZED_KEYS=/home/<user>/.ssh/authorized_keys
```

- `builtin` (default): Built-in SSH server supporting `exec`/`shell`, TCP port forwarding, Unix socket forwarding, and SFTP without system `sshd`.  
  `builtin`（默认）：内置 SSH 服务，无需系统 `sshd`，原生支持命令执行、TCP 端口转发、Unix Socket 转发与 SFTP。
- `local`: Proxies port 22 to the remote host's `127.0.0.1:22` OpenSSH `sshd`.  
  `local`：将 22 端口流量代理至远端本地的 OpenSSH `sshd`（`127.0.0.1:22`）。

### Step 5: Start the Gateway / 第五步：启动网关

- **Interactive / 前台运行：**
  ```bash
  ./net_world --env-file=.env.remote bridge
  ```
- **Persistent `systemd` service / 作为 `systemd` 后台常驻服务：**

  > **Important / 注意**：`net_world bridge` reads `stdin` for its outbound multiplexer and exits with status `0` on EOF. Under `systemd` (where `stdin` defaults to `/dev/null`), keep `stdin` open using `< <(sleep infinity)`.  
  > `net_world bridge` 会从 `stdin` 读取出站多路复用输入并在遇到 EOF 时以状态码 `0` 退出。在 `systemd` 中（默认 `stdin` 为 `/dev/null`），需使用 `< <(sleep infinity)` 保持 `stdin` 打开。

  ```ini
  [Unit]
  Description=net_world MeshBridge Service
  After=network-online.target
  Wants=network-online.target

  [Service]
  Type=simple
  User=<user>
  WorkingDirectory=/home/<user>/net_world
  ExecStart=/bin/bash -c 'exec /home/<user>/net_world/net_world --env-file=/home/<user>/net_world/.env.remote bridge < <(sleep infinity)'
  Restart=always
  RestartSec=3

  [Install]
  WantedBy=multi-user.target
  ```

Copy the `tc...` address printed in stdout/logs (`MeshBridge unified server listening on port 19100 (ssh=builtin): tc...`).  
从标准输出或日志（`journalctl -u net_world`）中复制 `tc...` 地址。

---

## 3. Local Machine Setup (Client) / 本地开发机接入（客户端）

### Option A: Write `~/.ssh/config` & Connect / 方式 A：写入 `~/.ssh/config` 后连接

1. **Generate and write the `Host` block / 生成并幂等写入 `Host` 配置块：**
   ```bash
   ./net_world -i ~/.ssh/id_ed25519 ssh-config --write <alias> <user>@<tc-addr>
   ```
2. **Verify SSH connectivity / 验证 SSH 连通性：**
   ```bash
   ssh <alias> "hostname && whoami"
   ```
3. **Connect in VS Code / 在 VS Code 中连接：**
   - **UI / 界面**：`Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` -> **Remote-SSH: Connect to Host...** -> select `<alias>`.
   - **CLI / 命令行**：
     ```bash
     code --remote ssh-remote+<alias> /path/to/workspace
     ```

### Option B: One-Line Launch with `net_world vscode` / 方式 B：使用 `net_world vscode` 一键拉起

```bash
./net_world -i ~/.ssh/id_ed25519 vscode <alias> <user>@<tc-addr> /path/to/workspace
```

> **Note / 注意**：`net_world vscode` requires `[user@]<tc-addr>` (with `<alias>` as an optional prefix); do not pass `<alias>` alone without `<tc-addr>`.  
> `net_world vscode` 必须传入 `[user@]<tc-addr>`（`<alias>` 仅为可选前缀），不能只传 SSH 别名。

---

## 4. Recommended VS Code Settings / 推荐 VS Code 配置

Add to your local VS Code `settings.json` when needed / 按需添加到本地 `settings.json`：

- **If the remote machine cannot download `~/.vscode-server` from the internet / 若远端机器无法访问外网下载 `~/.vscode-server`：**
  ```json
  "remote.SSH.localServerDownload": "always"
  ```
  VS Code downloads the server locally and uploads it over the `net_world` SSH/SFTP channel.  
  VS Code 会在本地下载 Server 压缩包，再通过 `net_world` 的 SSH/SFTP 通道上传至远端。

- **To use Unix Domain Socket forwarding / 若需启用 Unix Domain Socket 转发模式：**
  ```json
  "remote.SSH.remoteServerListenOnSocket": true
  ```

---

## 5. Management & Troubleshooting / 日常管理与排查

- **Check remote service status & `tc` address / 查看远端服务状态与 `tc` 地址：**
  ```bash
  ssh <alias> "sudo systemctl status net_world --no-pager"
  ssh <alias> "sudo journalctl -u net_world -n 30 --no-pager"
  ```
- **Update `tc` address in `~/.ssh/config` / 更新远端变化后的 `tc` 地址：**
  ```bash
  ./net_world -i ~/.ssh/id_ed25519 ssh-config --write <alias> <user>@<new-tc-addr>
  ```
- **Manual port forwarding / 手动转发额外端口：**
  ```bash
  ./net_world forward <tc-addr> 8080:8080
  ```
