# ip-self

`ip-self` 是一个用于管理 Linux IP 白名单的工具。控制 API 使用纯 HTTP，监听交互面板配置的 TCP 端口（默认 **38853**）。客户端向 `POST /v1/allow` 发送有效认证请求后，程序会把 TCP 直连来源 IP 加入交互面板所配置的业务端口防火墙白名单。

API 通过固定的 UUIDv7 Bearer Token 认证。HTTP 不加密，Token 会以明文在网络上传输，可能被同一网络路径上的第三方读取或重放；建议只在可信网络或 VPN 中使用，不要直接暴露在不可信公网。所选业务端口会设置为默认拒绝，再为白名单中的来源 IP 添加放行规则。控制端口不能作为业务端口。

## 安装与初始化

### 一键安装

适用于 Linux x86_64 和 ARM64。复制并运行：

```sh
installer="$(mktemp)" &&
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/llovely45/ip-self/main/install.sh -o "$installer" &&
sudo sh "$installer"
result=$?
rm -f "${installer:-}"
exit "$result"
```

安装脚本通过 HTTPS 下载 Linux 二进制文件和 `SHA256SUMS`，校验通过后安装到 `/usr/local/bin/ip-self`，并将更新器安装为 `/usr/local/bin/ip-self-install`。需要 `curl`、`sha256sum`（或 `shasum`）以及 root 权限。安装过程不会修改防火墙；安装后运行 `sudo ip-self`，通过交互面板检查并确认初始化配置。支持的架构为 `x86_64` 和 `aarch64`。

安装器支持手动控制版本：

```sh
sudo ip-self-install --update
sudo ip-self-install --version v0.2.3
ip-self version
```

不带参数或使用 `--update` 会安装最新 Release；`--version` 后指定 Release 标签可以安装或回退到该版本。安装器会先校验 SHA-256。升级不会修改配置文件；如果服务正在运行，替换二进制后还需要重启该服务才能运行新版本。

旧版安装如果还没有 `/usr/local/bin/ip-self-install`，请先重新运行上面的一键安装命令；安装器会一并安装更新命令。

从旧版本升级时不需要重新初始化。旧配置中的证书路径字段会为兼容保留但被忽略，API 将始终使用 HTTP。

也可以从 [GitHub Releases](https://github.com/llovely45/ip-self/releases) 手动下载并安装，或使用 Go 从源码安装：

```sh
go install github.com/llovely45/ip-self@latest
sudo install -m 0755 "$(go env GOPATH)/bin/ip-self" /usr/local/bin/ip-self
```

修改防火墙和使用默认配置路径需要 root 权限。运行以下命令打开面板：

```sh
sudo ip-self
```

选择 **初始化**。面板会要求配置：

1. HTTP API 监听地址，默认 `:38853`，端口可配置。使用 `:端口` 监听全部接口；也可以指定本机地址。
2. 服务器公网 IP/域名（可留空），用于生成可以直接复制的 curl 地址。
3. 要保护的业务 TCP 端口，例如 `22,80,443`。
4. 可选的初始可信来源 IP。
5. 选择 UFW、iptables 或 nftables，并输入 `APPLY` 明确确认应用规则。

所选业务端口默认拒绝白名单以外来源的连接。如果业务端口包含 SSH（`22`），请在初始化时加入当前管理 IP；否则，在建立新的 SSH 连接前，需要先从该 IP 成功调用 API。若初始白名单为空，所选业务端口的新连接会被拒绝，直到第一次 API 调用成功。

初始化时，程序会生成一个使用密码学安全随机数创建的 UUIDv7 Token，并以 `0600` 权限保存在受保护目录中的 `/etc/ip-self/config.json`。Token 创建后固定不变，面板不会覆盖它。请安全保存面板显示的 Token；之后可在面板选择 **显示 Token**，或运行 `sudo ip-self token` 查看。

选择 UFW 时，UFW 必须已经处于启用状态。`ip-self` 不会替你启用 UFW，因为这可能改变主机全局防火墙状态或中断 SSH。程序会把带有自身标记的规则放在所选端口已有规则之前。使用 iptables 或 nftables 时，UFW 必须未启用。iptables 后端管理 IPv4 和 IPv6 的 INPUT 链。nftables 后端使用自有的 `inet ipself` 表；如果发现其中存在没有 `ip-self` 所有权注释的规则，程序会拒绝替换该表。

在交互面板选择 **5) 后台启动 HTTP API 服务** 后，程序会分离启动服务、报告 PID 和日志路径，然后退出面板，不会继续占用当前终端。查看日志：

```sh
sudo tail -f /etc/ip-self/ip-self.log
```

停止后台服务时使用面板显示的 PID：

```sh
sudo kill <PID>
```

也可以在前台运行：

```sh
sudo ip-self serve
```

`serve` 会先重新应用已保存的防火墙策略，再启动监听。前台方式适合交给 systemd 等服务管理器运行；需要后台运行时使用面板的第 5 项。

选择 **6) 修改 HTTP API 监听端口** 可在初始化后调整控制端口。修改前需要先停止正在运行的 API 服务；程序会同步更新配置和它管理的防火墙规则。选择 **7) 显示 API 地址和 curl 命令** 可复制客户端调用示例。选择 **8) 设置 curl 使用的服务器 IP/域名** 可在初始化后补充或修改公网访问地址。若未设置公网地址，命令会使用 `YOUR_SERVER_IP_OR_DOMAIN` 占位符。

## API 调用

API 使用 TCP 连接的直连对端地址作为来源 IP。程序会忽略代理请求头，不接受请求体或客户端提供的目标 IP。默认端口的 API 地址示例为 `http://your-server.example:38853/v1/allow`。

```sh
printf 'Bearer Token: '
IFS= read -r -s IP_SELF_TOKEN
printf '\n'
printf 'header = "Authorization: Bearer %s"\n' "$IP_SELF_TOKEN" |
  curl --config - --fail-with-body --request POST \
  http://your-host.example:38853/v1/allow
unset IP_SELF_TOKEN
```

成功时会以 JSON 返回来源 IP 和已配置的端口。相同 IP 可以安全地重复调用。生成的防火墙规则会保存在配置中，并在 `ip-self serve` 启动时恢复。不要把 Token 放进 URL、Shell 历史记录、源代码仓库或日志中。上面的命令会隐藏 Token 输入，并通过标准输入交给 curl，避免 Token 出现在 curl 命令行参数中。

## 安全措施

- Bearer Token 使用恒定时间比较；成功和失败的请求都会受到速率限制。
- Token 使用 `crypto/rand` 生成，并符合 UUIDv7 格式。
- 配置文件以原子方式替换，并限制为文件所有者可访问。
- IP 地址会先解析并规范化，再作为防火墙命令参数传入。执行命令时不经过 Shell。
- API 仅接受空请求体的 `POST /v1/allow`，设置了请求超时和请求头大小上限，也不会记录 `Authorization` 请求头。
- API 使用明文 HTTP；不要在不可信网络中传输 Bearer Token。需要跨公网使用时，应先通过 VPN 或 SSH 隧道建立可信链路。
- 受保护端口的规则只影响主机 INPUT 流量，不会配置 Docker 转发、云安全组或上游网络防火墙。

## 自动构建

GitHub Actions 会在推送分支和 Pull Request 时，为支持的架构构建 Linux、macOS 和 Windows 二进制文件。推送 `v*` 格式的 tag 时，还会自动创建 GitHub Release，并上传编译产物及 SHA-256 校验文件。
