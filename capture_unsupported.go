//go:build !linux

package main

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

func newPlatformCapture(_ context.Context, _ *captureManager, _ []net.Interface) error {
	return fmt.Errorf("eBPF capture backend is only supported on Linux, current OS is %s", runtime.GOOS)
}
