//go:build !windows

package tcpowner

import "net"

func Snapshot(net.IP) (map[int][]Owner, string) { return nil, "unsupported_platform" }
