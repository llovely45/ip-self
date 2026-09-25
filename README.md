# ip-self

`ip-self` 是一个用于管理 Linux IP 白名单的工具。HTTP(S) 控制 API 监听 TCP **38853** 端口。客户端向 `POST /v1/allow` 发送有效认证请求后，程序会把 TCP 直连来源 IP 加入交互式面板所配置的业务端口防火墙白名单。

控制端口必须保持可连接，客户端才能完成认证。监听非回环地址时必须使用 TLS，并通过固定的 UUIDv7 Bearer Token 认证；仅监听回环地址时可使用 HTTP。所选业务端口会设置为默认拒绝，再为白名单中的来源 IP 添加放行规则。控制端口不能作为业务端口。

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
sudo ip-self-install --version v0.2.1
ip-self version
```

不带参数或使用 `--update` 会安装最新 Release；`--version` 后指定 Release 标签可以安装或回退到该版本。安装器会先校验 SHA-256。升级不会修改配置文件；如果服务正在运行，替换二进制后还需要重启该服务才能运行新版本。

旧版安装如果还没有 `/usr/local/bin/ip-self-install`，请先重新运行上面的一键安装命令；安装器会一并安装更新命令。

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

1. 监听地址，端口固定为 `38853`。
2. 如果监听地址不是回环地址，必须启用 TLS。可以使用已有证书和私钥，也可以让面板生成自签名证书。生成时需要填写客户端实际访问 API 时使用的域名/IP；私钥保存在 `/etc/ip-self/tls/server.key`，权限为 `0600`。
3. 要保护的业务 TCP 端口，例如 `22,80,443`。
4. 可选的初始可信来源 IP。
5. 选择 UFW、iptables 或 nftables，并输入 `APPLY` 明确确认应用规则。

所选业务端口默认拒绝白名单以外来源的连接。如果业务端口包含 SSH（`22`），请在初始化时加入当前管理 IP；否则，在建立新的 SSH 连接前，需要先从该 IP 成功调用 API。若初始白名单为空，所选业务端口的新连接会被拒绝，直到第一次 API 调用成功。

初始化时，程序会生成一个使用密码学安全随机数创建的 UUIDv7 Token，并以 `0600` 权限保存在受保护目录中的 `/etc/ip-self/config.json`。Token 创建后固定不变，面板不会覆盖它。请安全保存面板显示的 Token；之后可在面板选择 **显示 Token**，或运行 `sudo ip-self token` 查看。

自签名证书有效期为一年，保存在 `/etc/ip-self/tls/server.crt`。TLS 会加密连接，但自签名证书不会自动受到客户端信任。请通过安全渠道把证书复制到客户端，并在请求时使用 `curl --cacert`；客户端访问的域名/IP 必须与证书中的名称一致。不要使用 `-k` 或 `--insecure`，否则客户端不会验证服务器身份。面板会显示证书 SHA-256 指纹，便于通过可信渠道核对。

选择 UFW 时，UFW 必须已经处于启用状态。`ip-self` 不会替你启用 UFW，因为这可能改变主机全局防火墙状态或中断 SSH。程序会把带有自身标记的规则放在所选端口已有规则之前。使用 iptables 或 nftables 时，UFW 必须未启用。iptables 后端管理 IPv4 和 IPv6 的 INPUT 链。nftables 后端使用自有的 `inet ipself` 表；如果发现其中存在没有 `ip-self` 所有权注释的规则，程序会拒绝替换该表。

在交互面板选择 **5) 后台启动 API 服务** 后，程序会分离启动服务、报告 PID 和日志路径，然后退出面板，不会继续占用当前终端。查看日志：

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

## API 调用

API 使用 TCP 连接的直连对端地址作为来源 IP。程序会忽略代理请求头，不接受请求体或客户端提供的目标 IP。以下示例假设服务器使用客户端默认信任的 TLS 证书；自签名证书的调用方式见后文。

```sh
printf 'Bearer Token: '
IFS= read -r -s IP_SELF_TOKEN
printf '\n'
printf 'header = "Authorization: Bearer %s"\n' "$IP_SELF_TOKEN" |
  curl --config - --fail-with-body --request POST \
  https://your-host.example:38853/v1/allow
unset IP_SELF_TOKEN
```

成功时会以 JSON 返回来源 IP 和已配置的端口。相同 IP 可以安全地重复调用。生成的防火墙规则会保存在配置中，并在 `ip-self serve` 启动时恢复。

不要把 Token 放进 URL、Shell 历史记录、源代码仓库或日志中。监听非回环地址时必须使用 TLS。如果使用反向代理，防火墙看到的来源 IP 将是代理地址；程序有意不支持信任 `X-Forwarded-For`。

如果使用自签名证书，请先通过 SSH 或其他可信渠道把服务器的公有证书 `/etc/ip-self/tls/server.crt` 复制到发起请求的客户端，并确认客户端访问地址与证书中的 IP/域名一致。以下示例不会把 Token 写进命令历史或 `curl` 命令行参数：

```sh
printf 'Bearer Token: '
IFS= read -r -s IP_SELF_TOKEN
printf '\n'
printf 'header = "Authorization: Bearer %s"\n' "$IP_SELF_TOKEN" |
  curl --config - --cacert ./server.crt --fail-with-body --request POST \
  https://api.example.com:38853/v1/allow
unset IP_SELF_TOKEN
```

请替换为实际的 API 地址，并将 `./server.crt` 指向复制到客户端的证书。请求必须从希望加入白名单的网络发出；服务器只采用 TCP 直连来源 IP。

## 安全措施

- Bearer Token 使用恒定时间比较；成功和失败的请求都会受到速率限制。
- Token 使用 `crypto/rand` 生成，并符合 UUIDv7 格式。
- 配置文件以原子方式替换，并限制为文件所有者可访问。
- IP 地址会先解析并规范化，再作为防火墙命令参数传入。执行命令时不经过 Shell。
- API 仅接受空请求体的 `POST /v1/allow`，设置了请求超时和请求头大小上限，也不会记录 `Authorization` 请求头。
- 受保护端口的规则只影响主机 INPUT 流量，不会配置 Docker 转发、云安全组或上游网络防火墙。

## 自动构建

GitHub Actions 会在推送分支和 Pull Request 时，为支持的架构构建 Linux、macOS 和 Windows 二进制文件。推送 `v*` 格式的 tag 时，还会自动创建 GitHub Release，并上传编译产物及 SHA-256 校验文件。
