# wireguard-tools-go

A Go implementation of [wireguard-tools] based on the official [wgctrl] library.
For environments where the official tools are not readily available/buildable.

**DISCLAIMER: This is an unofficial implementation which by nature requires root privileges. Use at your own risk.**

## Usage

This project implements [wg(8)] as `wgg` (TODO: implement `wg-quick`). To use:

```shell
$ go build cmd/wgg/wgg.go
$ ./wgg --help
```

[wireguard-tools]: https://git.zx2c4.com/wireguard-tools/
[wgctrl]: https://pkg.go.dev/golang.zx2c4.com/wireguard/wgctrl
[wg(8)]: https://man7.org/linux/man-pages/man8/wg.8.html
