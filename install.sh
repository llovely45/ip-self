#!/bin/sh
# ip-self-installer
set -eu

usage() {
	cat <<'EOF'
用法：
  ip-self-install                 安装或升级到最新版本
  ip-self-install --update        升级到最新版本
  ip-self-install --version TAG   安装或升级到指定 Release 版本
  ip-self-install --help          显示帮助
EOF
}

requested_version=latest
case $# in
	0) ;;
	1)
		case $1 in
			--update|update) ;;
			--help|-h) usage; exit 0 ;;
			*) usage >&2; exit 2 ;;
		esac
		;;
	2)
		if [ "$1" != "--version" ]; then
			usage >&2
			exit 2
		fi
		requested_version=$2
		case $requested_version in
			v*) ;;
			*) printf '%s\n' '版本号必须是以 v 开头的 Release 标签，例如 v0.2.0。' >&2; exit 2 ;;
		esac
		case $requested_version in
			*[!A-Za-z0-9._+-]*) printf '%s\n' '版本标签包含不支持的字符。' >&2; exit 2 ;;
		esac
		;;
	*) usage >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
	printf '%s\n' '请使用 root 权限运行，例如：sudo ip-self-install --update' >&2
	exit 1
fi

os=$(uname -s)
if [ "$os" != "Linux" ]; then
	printf 'ip-self 防火墙管理需要 Linux（当前系统：%s）。\n' "$os" >&2
	exit 1
fi

case $(uname -m) in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*)
		printf '不支持的 CPU 架构：%s（支持 x86_64、aarch64）。\n' "$(uname -m)" >&2
		exit 1
		;;
esac

asset="ip-self_linux_$arch"
if [ "$requested_version" = latest ]; then
	base_url="https://github.com/llovely45/ip-self/releases/latest/download"
else
	base_url="https://github.com/llovely45/ip-self/releases/download/$requested_version"
fi

current_version=not-installed
if [ -x /usr/local/bin/ip-self ]; then
	current_version=$(/usr/local/bin/ip-self version 2>/dev/null || true)
	if [ -z "$current_version" ]; then
		current_version=unknown
	fi
fi
printf '当前版本：%s\n目标版本：%s\n' "$current_version" "$requested_version"

tmpdir=$(mktemp -d /tmp/ip-self-install.XXXXXX)
staged_binary="/usr/local/bin/.ip-self.$$"
staged_updater="/usr/local/bin/.ip-self-install.$$"
cleanup() {
	rm -rf "$tmpdir"
	rm -f "$staged_binary" "$staged_updater"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

download() {
	url=$1
	destination=$2
	curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location "$url" --output "$destination"
}

download "$base_url/$asset" "$tmpdir/$asset"
download "$base_url/SHA256SUMS" "$tmpdir/SHA256SUMS"
service_available=yes
if ! download "$base_url/ip-self.service" "$tmpdir/ip-self.service" 2>/dev/null; then
	if [ "$requested_version" = latest ]; then
		printf '%s\n' '最新 Release 缺少 ip-self.service，已取消安装。' >&2
		exit 1
	fi
	service_available=no
	printf '%s\n' '指定的旧版 Release 不含 systemd 单元，继续按旧版手动启动模式安装。'
fi

expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$tmpdir/SHA256SUMS")
case $expected in
	????????????????????????????????????????????????????????????????) ;;
	*) printf '%s\n' '校验文件中没有找到该二进制对应的有效 SHA-256 记录。' >&2; exit 1 ;;
esac
case $expected in
	*[!0123456789abcdefABCDEF]*) printf '%s\n' 'Release 校验值格式错误。' >&2; exit 1 ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "$tmpdir/$asset" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
	actual=$(shasum -a 256 "$tmpdir/$asset" | awk '{ print $1 }')
else
	printf '%s\n' '请先安装 sha256sum 或 shasum。' >&2
	exit 1
fi
if [ "$actual" != "$expected" ]; then
	printf '%s\n' 'SHA-256 校验失败，已取消安装。' >&2
	exit 1
fi

if [ "$service_available" = yes ]; then
	expected_service=$(awk '$2 == "ip-self.service" { print $1 }' "$tmpdir/SHA256SUMS")
	case $expected_service in
		????????????????????????????????????????????????????????????????) ;;
		*) printf '%s\n' '校验文件中没有找到 systemd 服务单元对应的有效 SHA-256 记录。' >&2; exit 1 ;;
	esac
	case $expected_service in
		*[!0123456789abcdefABCDEF]*) printf '%s\n' 'systemd 服务单元校验值格式错误。' >&2; exit 1 ;;
	esac
	if command -v sha256sum >/dev/null 2>&1; then
		actual_service=$(sha256sum "$tmpdir/ip-self.service" | awk '{ print $1 }')
	else
		actual_service=$(shasum -a 256 "$tmpdir/ip-self.service" | awk '{ print $1 }')
	fi
	if [ "$actual_service" != "$expected_service" ]; then
		printf '%s\n' 'systemd 服务单元 SHA-256 校验失败，已取消安装。' >&2
		exit 1
	fi
fi

install -d -m 0755 /usr/local/bin
if [ "$service_available" = yes ]; then
	install -d -m 0755 /etc/systemd/system
fi

script_source=
case $0 in
	/*) script_source=$0 ;;
	*) script_source="$(pwd)/$0" ;;
esac
if [ -f "$script_source" ] && [ ! -L "$script_source" ] &&
	[ "$(sed -n '2p' "$script_source")" = '# ip-self-installer' ]; then
	install -m 0755 "$script_source" "$staged_updater"
	mv -f "$staged_updater" /usr/local/bin/ip-self-install
	else
	installer_ref=main
	if [ "$requested_version" != latest ]; then
		installer_ref=$requested_version
	fi
	download "https://raw.githubusercontent.com/llovely45/ip-self/$installer_ref/install.sh" "$tmpdir/ip-self-install"
	install -m 0755 "$tmpdir/ip-self-install" "$staged_updater"
	mv -f "$staged_updater" /usr/local/bin/ip-self-install
fi

install -m 0755 "$tmpdir/$asset" "$staged_binary"
mv -f "$staged_binary" /usr/local/bin/ip-self
if [ "$service_available" = yes ]; then
	install -m 0644 "$tmpdir/ip-self.service" /etc/systemd/system/ip-self.service
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && [ -f /etc/systemd/system/ip-self.service ]; then
	systemctl daemon-reload
	systemctl enable ip-self.service
	if [ -f /etc/ip-self/config.json ]; then
		systemctl restart ip-self.service
		printf '%s\n' 'systemd API 服务已启动并设置为开机启动；异常退出后将自动重启。'
	else
		printf '%s\n' 'systemd 服务已安装并启用；初始化配置后会自动启动 API。'
	fi
elif [ "$service_available" = yes ]; then
	printf '%s\n' 'systemd 服务单元已安装；当前未检测到运行中的 systemd，保留原有手动后台启动方式。'
fi

installed_version=$(/usr/local/bin/ip-self version 2>/dev/null || printf '%s' "$requested_version")
printf '已安装 ip-self %s（%s）到 /usr/local/bin/ip-self\n' "$installed_version" "$arch"
if [ -x /usr/local/bin/ip-self-install ]; then
	printf '%s\n' '手动升级到最新版本：sudo ip-self-install --update'
	printf '%s\n' '安装指定版本：sudo ip-self-install --version v0.2.6'
fi
printf '%s\n' '运行 sudo ip-self 打开初始化面板。'
