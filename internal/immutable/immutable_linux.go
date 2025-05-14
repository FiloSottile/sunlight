//go:build amd64 || arm64

// Package immutable provides best-effort support for setting and unsetting the
// immutable flag on files.
package immutable

import (
	"os"
	"syscall"
	"unsafe"
)

const _FS_IOC_SETFLAGS = uintptr(0x40086602)
const _FS_IMMUTABLE_FL = 0x00000010

func Set(f *os.File) {
	setFlags(f, _FS_IMMUTABLE_FL)
}

func Unset(f *os.File) {
	setFlags(f, 0)
}

func setFlags(f *os.File, flags int32) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), _FS_IOC_SETFLAGS, uintptr(unsafe.Pointer(&flags)))
}
