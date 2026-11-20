// Package tcpowner reads local IPv4 listener ownership. It never inspects a
// remote machine or infers a process from a well-known port number.
package tcpowner

import (
	"encoding/binary"
	"errors"
	"net"
)

type Owner struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name,omitempty"`
}

// parseTable decodes the Windows MIB_TCPTABLE_OWNER_PID layout: DWORD count,
// then six DWORDs per row. IP and port bytes are in network order.
func parseTable(b []byte, ip net.IP, names map[uint32]string) (map[int][]Owner, error) {
	if len(b) < 4 || uint64(binary.LittleEndian.Uint32(b)) > uint64((len(b)-4)/24) {
		return nil, errors.New("invalid TCP ownership table")
	}
	out := make(map[int][]Owner)
	for i := 0; i < int(binary.LittleEndian.Uint32(b)); i++ {
		r := b[4+i*24 : 4+(i+1)*24]
		if binary.LittleEndian.Uint32(r) != 2 {
			continue
		}
		addr := net.IP(r[4:8])
		if !addr.IsUnspecified() && !addr.Equal(ip) {
			continue
		}
		port := int(binary.BigEndian.Uint16(r[8:10]))
		pid := binary.LittleEndian.Uint32(r[20:24])
		duplicate := false
		for _, old := range out[port] {
			if old.PID == pid {
				duplicate = true
			}
		}
		if !duplicate {
			out[port] = append(out[port], Owner{pid, names[pid]})
		}
	}
	return out, nil
}
