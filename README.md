# net-peek

`net-peek` is a Go TUI for watching per-remote-IP traffic usage on one network interface or all interfaces.

It shows:

- inbound and outbound rate per IP;
- total inbound and outbound bytes since start;
- established connection count per remote IP;
- connection details when an IP is opened with `enter`.

## Requirements

- Go 1.22+
- `libpcap` development headers
- packet-capture privileges

On Linux you can usually run it with `sudo`, or grant capture capabilities to the built binary:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip ./net-peek
```

## Install

Using the latest GitHub release:

```sh
curl -fsSL https://raw.githubusercontent.com/itcaat/net-peek/main/install.sh | sh
```

Install into a custom directory:

```sh
curl -fsSL https://raw.githubusercontent.com/itcaat/net-peek/main/install.sh | BIN_DIR="$HOME/.local/bin" sh
```

Install a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/itcaat/net-peek/main/install.sh | VERSION="v0.1.0" sh
```

Install the latest beta release:

```sh
curl -fsSL https://raw.githubusercontent.com/itcaat/net-peek/main/install.sh | VERSION="beta" sh
```

On a remote server:

```sh
go install github.com/itcaat/net-peek@latest
```

This installs the `net-peek` binary into `GOBIN`, or into `$(go env GOPATH)/bin` when `GOBIN` is not set. Make sure that directory is in `PATH`:

```sh
export PATH="$(go env GOPATH)/bin:$PATH"
```

Then run:

```sh
sudo net-peek -i all
sudo net-peek -i eth0
```

On Debian/Ubuntu servers, install build requirements first:

```sh
sudo apt-get update
sudo apt-get install -y golang libpcap-dev
```

On RHEL/Fedora:

```sh
sudo dnf install -y golang libpcap-devel
```

If you prefer Linux capabilities instead of `sudo`, build a local binary and grant capture permissions:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v net-peek)"
net-peek -i all
```

From a local repository checkout, you can also install the current working tree:

```sh
go install .
```

## Releases

GitHub releases are created automatically when a version tag is pushed:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds native artifacts for Linux and macOS on both `amd64` and `arm64`. Because `net-peek` uses `libpcap`, release builds use native GitHub Actions runners instead of CGO cross-compilation.

Release assets:

- `net-peek_<tag>_linux_amd64.tar.gz`
- `net-peek_<tag>_linux_arm64.tar.gz`
- `net-peek_<tag>_darwin_amd64.tar.gz`
- `net-peek_<tag>_darwin_arm64.tar.gz`
- `checksums.txt`

The same release flow is available through `make`:

```sh
make test
make build
make next-tag
make release
```

Beta releases use prerelease tags:

```sh
make next-beta
make beta
```

`make beta` creates tags like `v0.1.0-beta.1` and GitHub publishes them as prereleases.

## Usage

```sh
go run . -list
sudo go run . -i all
sudo go run . -i eth0
```

Gateway/NAT mode counts all captured traffic by source and destination IP:

```sh
sudo go run . --mode gateway
```

In gateway mode, every captured packet is counted twice: source IP gets `Out`, destination IP gets `In`. By default this captures `all` interfaces. Use `-i` only when you want to restrict it to one interface:

```sh
sudo go run . --mode gateway -i zt0
```

Connection counts still describe local host sockets; NAT conntrack support is not implemented yet.

Keys:

- `enter`: open the selected IP and show its connections
- `backspace`, `esc`, `left`: return from an IP connection view to the IP list
- `tab`: open or close interface selector
- `/`: search or filter IPs
- `enter`: open the selected IP while searching
- `esc`: clear search input while searching
- arrow keys: navigate rows while searching
- `space`: pause or resume table updates
- `+`: shorter rolling average window
- `-`: longer rolling average window
- `i`: sort by IP
- `c`: sort by connection count
- `r`: sort by inbound rate
- `o`: sort by outbound rate
- `n`: sort by total inbound bytes
- `u`: sort by total outbound bytes
- `t`: sort by total bytes
- `q`, `ctrl+c`: quit
- `esc`: quit from the IP list

## Notes

Traffic is counted from captured packets after the program starts. Connection counts are collected from `/proc/net/tcp*` on Linux, `lsof` on macOS, and `netstat` as a fallback, then grouped by remote IP.
