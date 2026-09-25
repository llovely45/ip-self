# ip-self

`ip-self` is a small Linux IP allowlist controller. Its HTTPS control API listens on TCP port **38853**. After a valid authenticated `POST /v1/allow`, it adds the direct peer IP to the firewall allowlist for the TCP ports selected in the interactive panel.

The control port must remain reachable so clients can authenticate. It is protected by TLS and a fixed UUIDv7 Bearer token. The selected business ports receive a default-deny rule, followed by source-IP allow rules. The control port cannot be selected as a business port.

## Install and initialize

### One-line installer

On Linux x86_64 or ARM64, run:

```sh
installer="$(mktemp)" &&
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/llovely45/ip-self/main/install.sh -o "$installer" &&
sudo sh "$installer"
result=$?
rm -f "${installer:-}"
exit "$result"
```

The installer downloads the latest Linux binary and `SHA256SUMS` over HTTPS, verifies the checksum, and installs to `/usr/local/bin/ip-self`. It requires `curl`, `sha256sum` (or `shasum`), and root privileges. It does not configure the firewall; run `sudo ip-self` after installation to review and apply the setup interactively. The supported architectures are `x86_64` and `aarch64`.

You can also download an asset from [GitHub Releases](https://github.com/llovely45/ip-self/releases) and install it manually, or install from source with Go:

```sh
go install github.com/llovely45/ip-self@latest
sudo install -m 0755 "$(go env GOPATH)/bin/ip-self" /usr/local/bin/ip-self
```

Firewall changes and the default configuration path require root. Open the panel with:

```sh
sudo ip-self
```

Choose **Initialize**. The panel asks for:

1. The listener address on port `38853`.
2. TLS certificate and private key paths when listening beyond loopback. The private key must be readable only by its owner (for example, mode `0600`).
3. The business TCP ports to protect, such as `22,80,443`.
4. Optional initial trusted source IPs.
5. UFW, iptables, or nftables, then an explicit `APPLY` confirmation.

Selected business ports default to deny for every IP outside the allowlist. If the list includes SSH (`22`), add your current management IP during setup or be ready to call the API from that IP before opening a new SSH connection. An empty initial list denies new connections to all selected business ports until the first successful API call.

Initialization creates one cryptographically random UUIDv7 token and stores it in `/etc/ip-self/config.json` with mode `0600` in a protected directory. The token is fixed after creation; the panel will not overwrite it. Save the displayed token securely. Use **Show Token** in the panel or `sudo ip-self token` to read it later.

UFW must already be active; `ip-self` will not enable UFW because doing so can change host-wide firewall state or interrupt SSH. When UFW is selected, ip-self places its tagged rules before existing rules for the selected ports. For iptables and nftables, UFW must not be active. The iptables backend manages both IPv4 and IPv6 INPUT chains. The nftables backend owns the `inet ipself` table; it refuses to replace that table if it finds rules without ip-self ownership comments.

Start the API from the panel or run:

```sh
sudo ip-self serve
```

The `serve` command reapplies the saved firewall policy before opening the listener. Keep it running so requests can be handled. Configure your service manager to start `ip-self serve` after boot if you want iptables/nftables rules restored automatically after a reboot.

## API

The API derives the address from the TCP connection's direct peer. It ignores proxy headers and accepts no client-supplied IP or request body.

```sh
printf 'Token: '
read -r -s IP_SELF_TOKEN
printf '\n'
curl --fail-with-body -X POST \
  -H "Authorization: Bearer ${IP_SELF_TOKEN}" \
  https://your-host.example:38853/v1/allow
unset IP_SELF_TOKEN
```

Success returns the peer IP and configured ports as JSON. The same IP can call the endpoint again safely. The resulting firewall rules persist in the config and are restored when `ip-self serve` starts.

Do not put the token in a URL, shell history, source control, or logs. Direct TLS is required for non-loopback listeners. If a reverse proxy is used, the firewall sees the proxy's address; trusting `X-Forwarded-For` is intentionally unsupported.

## Security behavior

- Bearer authentication uses constant-time comparison; failed and successful requests are rate-limited.
- Tokens are generated with `crypto/rand` and use the UUIDv7 layout.
- Config files are atomically replaced and restricted to owner access.
- IP addresses are parsed and canonicalized before being passed as firewall arguments. Commands run directly without a shell.
- The handler accepts only an empty-body `POST /v1/allow`, applies request timeouts and a header-size limit, and never logs the Authorization header.
- Protected-port rules affect host INPUT traffic only. They do not configure Docker forwarding, cloud security groups, or upstream network firewalls.

## Build automation

GitHub Actions builds Linux, macOS, and Windows binaries for supported architectures on pushes and pull requests. Pushing a `v*` tag also creates a GitHub Release with the compiled binaries and SHA-256 checksums.
