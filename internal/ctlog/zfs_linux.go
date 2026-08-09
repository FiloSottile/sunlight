package ctlog

import "syscall"

// onZFS reports whether the filesystem containing dir is ZFS.
func onZFS(dir string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false
	}
	// ZFS_SUPER_MAGIC, the statfs(2) f_type of OpenZFS filesystems.
	return uint32(st.Type) == 0x2fc12fc1
}
