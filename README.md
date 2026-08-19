# net-peek

`net-peek` is a Linux eBPF TUI for watching per-IP traffic usage on one network interface or all interfaces.

It shows:

- inbound and outbound rate per IP in host mode;
- gateway/NAT consumer traffic in gateway mode;
- total inbound and outbound bytes since start;
- established connection count per remote IP;
- destination flow details when a gateway client is opened with `enter`.

## Requirements

- Go 1.23+
- Linux with eBPF support
- root or `CAP_BPF`/`CAP_NET_ADMIN` privileges

`net-peek` uses TC eBPF programs attached to ingress and egress of selected interfaces. It does not require `libpcap`, `tcpdump`, `ss`, or `tc`.

The current backend uses TCX attach, which requires Linux 6.6 or newer.

You can usually run it with `sudo`:

```sh
sudo net-peek
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

On a Linux server:

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
sudo net-peek --mode gateway
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

The release workflow builds Linux artifacts for `amd64` and `arm64`. Release binaries include the compiled eBPF program, so installing from releases does not require clang or kernel headers.

Release assets:

- `net-peek_<tag>_linux_amd64.tar.gz`
- `net-peek_<tag>_linux_arm64.tar.gz`
- `checksums.txt`

The same release flow is available through `make`:

```sh
make test
make build
make build-linux
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

Gateway/NAT mode shows internal consumers:

```sh
sudo go run . --mode gateway
```

Gateway mode classifies client traffic from TC direction:

- `Down/s`: traffic egressing from the gateway to a directly connected private/CGNAT/ULA client.
- `Up/s`: traffic ingressing into the gateway from a directly connected private/CGNAT/ULA client.
- `Enter`: opens destination flows for the selected client.

By default this attaches to all non-loopback interfaces. Use `-i` to restrict it to one interface:

```sh
sudo go run . --mode gateway -i zt0
```

Gateway mode intentionally does not show public endpoints or other routed private networks as top-level consumers unless they are directly connected to the selected interface subnet.

Keys:

- `enter`: open the selected IP and show its connections
- `backspace`, `esc`, `left`: return from an IP connection view to the IP list
- `m`: switch between host and gateway mode
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

Traffic is counted from eBPF flow counters after the program starts. Host-mode connection counts are collected from `/proc/net/tcp*` on Linux and grouped by remote IP.

For eBPF development, regenerate the embedded BPF object after changing `bpf/netpeek.c`:

```sh
make generate
```

Generated release/install builds do not need this step.
