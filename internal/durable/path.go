// Package durable provides equivalent functionality to the os package, but with
// additional guarantees for durability based on [os.File.Sync].
//
// Note that after an fsync error, files and caches may be in a number of
// unreliable states, such that the only potentially safe course of action is
// starting over without reading back the failed files.
//
// See also https://www.usenix.org/conference/atc20/presentation/rebello,
// https://wiki.postgresql.org/wiki/Fsync_Errors, and
// https://danluu.com/deconstruct-files/.
package durable

import (
	"os"
	"path/filepath"
	"syscall"
)

// The sequence of syscalls for a happy path call to WriteFile looks like this:
//
//     openat(AT_FDCWD, "dir", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3
//     openat(AT_FDCWD, "dir/.file4057926228", O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 6
//     fchmod(6, 0644)                         = 0
//     write(6, "hello world", 11)             = 11
//     fsync(6)                                = 0
//     close(6)                                = 0
//     renameat(AT_FDCWD, "dir/.file4057926228", AT_FDCWD, "dir/file") = 0
//     fsync(3)                                = 0
//     close(3)                                = 0
//

// WriteFile behaves somewhat like [os.WriteFile], but it also syncs the file
// contents and the directory entry to disk before returning, and prevents
// partial writes from being visible.
//
// If the file already exists, it takes the specified permissions.
func WriteFile(name string, data []byte, perm os.FileMode) (err error) {
	// After the file, sync the directory in which the entry resides. Otherwise,
	// after a power failure the file may not exist or the rename may rollback.
	//
	// Keep the parent open during the operation, to prevent it from being
	// evicted from the inode cache, which can discard a write-through error.
	parent, err := os.OpenFile(filepath.Dir(name), os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return &os.PathError{Op: "durablewrite", Path: name, Err: err}
	}
	defer fsyncAndClose(parent, &err)

	f, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name))
	if err != nil {
		return &os.PathError{Op: "durablewrite", Path: name, Err: err}
	}
	defer func(tmpname string) {
		if err == nil {
			err = os.Rename(tmpname, name)
		}
		if err != nil {
			os.Remove(tmpname)
		}
	}(f.Name())
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	defer fsyncAndClose(f, &err)

	_, err = f.Write(data)
	return err
}

// MkdirAll behaves like [os.MkdirAll], but it also syncs each affected
// directory to disk.
func MkdirAll(path string, perm os.FileMode) (err error) {
	if dir, err := os.Stat(path); err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	path = filepath.Clean(path)
	if parent := filepath.Dir(path); parent != path && parent != filepath.VolumeName(path) {
		if err := MkdirAll(parent, perm); err != nil {
			return err
		}
	}

	// This is a little inefficient because if we are creating two levels of
	// directories, we will sync the intermediate directory twice. That's going
	// to be rare in our use case, so we don't optimize for it.
	return Mkdir(path, perm)
}

// The sequence of syscalls for a happy path call to Mkdir looks like this:
//
//     openat(AT_FDCWD, "dir1", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3
//     mkdirat(AT_FDCWD, "dir1/dir2", 0755)    = 0
//     openat(AT_FDCWD, "dir1/dir2", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 6
//     fsync(6)                                = 0
//     close(6)                                = 0
//     fsync(3)                                = 0
//     close(3)                                = 0
//

// Mkdir behaves like [os.Mkdir], but it also syncs the directory and its parent
// to disk. Unlike [os.Mkdir], it returns nil if the directory already exists to
// prevent returning errors in case of races.
func Mkdir(path string, perm os.FileMode) (err error) {
	parent, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	defer fsyncAndClose(parent, &err)

	if err := os.Mkdir(path, perm); err != nil && !os.IsExist(err) {
		return err
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	defer fsyncAndClose(f, &err)

	return nil
}

func fsyncAndClose(f *os.File, err *error) {
	if *err == nil {
		*err = f.Sync()
	}
	if err1 := f.Close(); err1 != nil && *err == nil {
		*err = err1
	}
}
