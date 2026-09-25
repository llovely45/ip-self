#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	printf '%s\n' 'Run this installer as root, for example: curl ... | sudo sh' >&2
	exit 1
fi

os=$(uname -s)
if [ "$os" != "Linux" ]; then
	printf 'ip-self firewall management requires Linux (detected %s).\n' "$os" >&2
	exit 1
fi

case $(uname -m) in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*)
		printf 'Unsupported CPU architecture: %s (supported: x86_64, aarch64).\n' "$(uname -m)" >&2
		exit 1
		;;
esac

asset="ip-self_linux_${arch}"
base_url="https://github.com/llovely45/ip-self/releases/latest/download"
tmpdir=$(mktemp -d /tmp/ip-self-install.XXXXXX)
trap 'rm -rf "$tmpdir"' 0
trap 'exit 1' HUP INT TERM

download() {
	url=$1
	destination=$2
	curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location "$url" --output "$destination"
}

download "${base_url}/${asset}" "${tmpdir}/${asset}"
download "${base_url}/SHA256SUMS" "${tmpdir}/SHA256SUMS"

expected=$(awk -v name="$asset" '$2 == name { print $1 }' "${tmpdir}/SHA256SUMS")
case $expected in
	????????????????????????????????????????????????????????????????) ;;
	*) printf '%s\n' 'Could not find a valid SHA-256 entry for the downloaded binary.' >&2; exit 1 ;;
esac
case $expected in
	*[!0123456789abcdefABCDEF]*) printf '%s\n' 'The release checksum is malformed.' >&2; exit 1 ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "${tmpdir}/${asset}" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
	actual=$(shasum -a 256 "${tmpdir}/${asset}" | awk '{ print $1 }')
else
	printf '%s\n' 'Install sha256sum or shasum before running this installer.' >&2
	exit 1
fi
if [ "$actual" != "$expected" ]; then
	printf '%s\n' 'SHA-256 verification failed; refusing to install.' >&2
	exit 1
fi

install -d -m 0755 /usr/local/bin
install -m 0755 "${tmpdir}/${asset}" /usr/local/bin/ip-self
printf 'Installed ip-self (%s) to /usr/local/bin/ip-self\n' "$arch"
printf '%s\n' 'Run `sudo ip-self` to open the setup panel.'
