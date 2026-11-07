//go:build windows

// memdump copies the in-memory image of a running 32-bit process (read
// only) so code that is encrypted on disk can be analysed with ssre.
//
//	memdump <pid> <base-hex> <size-hex> <out-file>
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
	memCommit               = 0x1000
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: memdump <pid> <base-hex> <size-hex> <out-file>")
		os.Exit(2)
	}
	pid, _ := strconv.Atoi(os.Args[1])
	base, _ := strconv.ParseUint(os.Args[2], 16, 64)
	size, _ := strconv.ParseUint(os.Args[3], 16, 64)

	k32 := syscall.NewLazyDLL("kernel32.dll")
	openProcess := k32.NewProc("OpenProcess")
	readMem := k32.NewProc("ReadProcessMemory")
	virtualQuery := k32.NewProc("VirtualQueryEx")

	h, _, err := openProcess.Call(processQueryInformation|processVMRead, 0, uintptr(pid))
	if h == 0 {
		fmt.Fprintln(os.Stderr, "OpenProcess:", err)
		os.Exit(1)
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	out := make([]byte, size)
	var read, skipped uint64
	for addr := base; addr < base+size; {
		var mbi memoryBasicInformation
		r, _, _ := virtualQuery.Call(h, uintptr(addr), uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
		if r == 0 {
			break
		}
		end := uint64(mbi.BaseAddress) + uint64(mbi.RegionSize)
		if end > base+size {
			end = base + size
		}
		n := end - addr
		if mbi.State == memCommit {
			var got uintptr
			ok, _, _ := readMem.Call(h, uintptr(addr), uintptr(unsafe.Pointer(&out[addr-base])), uintptr(n), uintptr(unsafe.Pointer(&got)))
			if ok != 0 {
				read += uint64(got)
			} else {
				skipped += n
			}
		} else {
			skipped += n
		}
		addr = end
	}
	if err := os.WriteFile(os.Args[4], out, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("read %d bytes, skipped %d\n", read, skipped)
}
