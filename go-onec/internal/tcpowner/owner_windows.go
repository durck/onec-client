package tcpowner

import (
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"syscall"
	"unsafe"
)

var getExtendedTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// Snapshot is intentionally limited to loopback IPv4 targets. This prevents
// attributing a remote listener to an unrelated local process using its port.
func Snapshot(ip net.IP) (map[int][]Owner, string) {
	if !ip.IsLoopback() || ip.To4() == nil {
		return nil, "not_loopback"
	}
	if err := getExtendedTCPTable.Find(); err != nil {
		return nil, "unavailable"
	}
	var size uint32
	r, _, _ := getExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 3, 0)
	if syscall.Errno(r) != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, "unavailable"
	}
	for attempt := 0; attempt < 3; attempt++ {
		if size < 4 || size > 16*1024*1024 {
			return nil, "invalid_table"
		}
		b := make([]byte, size)
		r, _, _ = getExtendedTCPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 3, 0)
		if syscall.Errno(r) == windows.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		if r != 0 || size > uint32(len(b)) {
			return nil, "unavailable"
		}
		names := processNames()
		owners, err := parseTable(b[:size], ip, names)
		if err != nil {
			return nil, "invalid_table"
		}
		return owners, "snapshot"
	}
	return nil, "table_changed"
}

func processNames() map[uint32]string {
	names := make(map[uint32]string)
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return names
	}
	defer windows.CloseHandle(h)
	var p windows.ProcessEntry32
	p.Size = uint32(unsafe.Sizeof(p))
	err = windows.Process32First(h, &p)
	for err == nil {
		names[p.ProcessID] = windows.UTF16ToString(p.ExeFile[:])
		err = windows.Process32Next(h, &p)
	}
	if err != nil && !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil
	}
	return names
}
