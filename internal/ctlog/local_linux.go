//go:build amd64 || arm64

package ctlog

import (
	"os"
	"syscall"
	"unsafe"
)

const _FS_IOC_SETFLAGS = uintptr(0x40086602)
const _FS_IMMUTABLE_FL = 0x00000010

func setImmutable(name string) {
	f, err := os.Open(name)
	if err != nil {
		return
	}
	defer f.Close()
	setFlags(f, _FS_IMMUTABLE_FL)
}

func unsetImmutable(name string) {
	f, err := os.Open(name)
	if err != nil {
		return
	}
	defer f.Close()
	setFlags(f, 0)
}

func setFlags(f *os.File, flags int32) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), _FS_IOC_SETFLAGS, uintptr(unsafe.Pointer(&flags)))
}
