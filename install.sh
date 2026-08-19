#!/usr/bin/env sh
set -eu

REPO="${REPO:-itcaat/net-peek}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"
CHANNEL="${CHANNEL:-}"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

need curl
need tar

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
linux) os="linux" ;;
*)
	echo "unsupported OS: $os; net-peek uses Linux eBPF" >&2
	exit 1
	;;
esac

arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) arch="amd64" ;;
arm64 | aarch64) arch="arm64" ;;
*)
	echo "unsupported architecture: $arch" >&2
	exit 1
	;;
esac

if [ -z "$CHANNEL" ] && [ "$VERSION" = "beta" ]; then
	CHANNEL="beta"
fi
if [ -z "$CHANNEL" ]; then
	CHANNEL="stable"
fi

if [ "$VERSION" = "latest" ] && [ "$CHANNEL" = "stable" ]; then
	api_url="https://api.github.com/repos/$REPO/releases/latest"
	tag="$(curl -fsSL "$api_url" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
	if [ -z "$tag" ]; then
		echo "failed to resolve latest release tag for $REPO" >&2
		exit 1
	fi
elif [ "$CHANNEL" = "beta" ]; then
	api_url="https://api.github.com/repos/$REPO/releases?per_page=100"
	tag="$(curl -fsSL "$api_url" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*-beta\.[0-9][^"]*\)".*/\1/p' | head -n 1)"
	if [ -z "$tag" ]; then
		echo "failed to resolve latest beta release tag for $REPO" >&2
		exit 1
	fi
else
	tag="$VERSION"
fi

asset="net-peek_${tag}_${os}_${arch}.tar.gz"
base_url="https://github.com/$REPO/releases/download/$tag"
tmp_dir="$(mktemp -d)"
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

echo "Installing net-peek $tag for $os/$arch"
curl -fL "$base_url/$asset" -o "$tmp_dir/$asset"
curl -fL "$base_url/checksums.txt" -o "$tmp_dir/checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
	(cd "$tmp_dir" && sha256sum -c checksums.txt --ignore-missing)
elif command -v shasum >/dev/null 2>&1; then
	expected="$(grep "  $asset\$" "$tmp_dir/checksums.txt" | awk '{print $1}')"
	actual="$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')"
	if [ "$expected" != "$actual" ]; then
		echo "checksum mismatch for $asset" >&2
		exit 1
	fi
else
	echo "warning: sha256sum or shasum not found; skipping checksum verification" >&2
fi

tar -xzf "$tmp_dir/$asset" -C "$tmp_dir"

if [ ! -d "$BIN_DIR" ]; then
	mkdir -p "$BIN_DIR"
fi

if [ -w "$BIN_DIR" ]; then
	install -m 0755 "$tmp_dir/net-peek" "$BIN_DIR/net-peek"
else
	need sudo
	sudo install -m 0755 "$tmp_dir/net-peek" "$BIN_DIR/net-peek"
fi

echo "Installed: $BIN_DIR/net-peek"
"$BIN_DIR/net-peek" --version
