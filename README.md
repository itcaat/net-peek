# net-peek

`net-peek` is a Go TUI for watching per-remote-IP traffic usage on one network interface or all interfaces.

It shows:

- inbound and outbound rate per IP;
- total inbound and outbound bytes since start;
- established connection count per remote IP;
- connection details when `d` is pressed.

## Requirements

- Go 1.22+
- `libpcap` development headers
- packet-capture privileges

On Linux you can usually run it with `sudo`, or grant capture capabilities to the built binary:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip ./net-peek
```

## Install

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

The release workflow builds Linux release artifacts with GoReleaser. Because `net-peek` uses `libpcap`, release builds require CGO and currently publish Linux `amd64` binaries.

The same release flow is available through `make`:

```sh
make test
make build
make next-tag
make release
```

## Usage

```sh
go run . -list
sudo go run . -i all
sudo go run . -i eth0
```

Keys:

- `enter`: open the selected IP and show its connections
- `backspace`, `esc`, `left`: return from an IP connection view to the IP list
- `space`: pause or resume table updates
- `1`: sort by IP
- `2`: sort by connection count
- `3`: sort by inbound rate
- `4`: sort by outbound rate
- `5`: sort by total inbound bytes
- `6`: sort by total outbound bytes
- `7`: sort by total bytes
- `q`, `ctrl+c`: quit
- `esc`: quit from the IP list

## Notes

Traffic is counted from captured packets after the program starts. Connection counts are collected from `ss` on Linux and `netstat` elsewhere, then grouped by remote IP.
