// Package durable provides equivalent functionality to the os package, but with
// additional guarantees for durability based on [os.File.Sync].
package durable

import (
	"os"
	"path/filepath"
	"syscall"
)

// WriteFile behaves like [os.WriteFile], but it also syncs the file contents
// and the directory containing the file to disk.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	if err == nil {
		// Note that this is not necessary if the file was not just created.
		// Our use of this function is mostly for creating new files, so we
		// don't optimize for the case where the file already exists.
		err = fsyncDirectory(name)
	}
	return err
}

// MkdirAll behaves like [os.MkdirAll], but it also syncs the directory
// containing each created directory to disk.
func MkdirAll(path string, perm os.FileMode) error {
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

	return Mkdir(path, perm)
}

// Mkdir behaves like [os.Mkdir], but it also syncs the directory containing
// the created directory to disk.
func Mkdir(path string, perm os.FileMode) (err error) {
	defer func() {
		if err == nil {
			err = fsyncDirectory(path)
		}
	}()

	// Do we need to sync path itself? Presumably not, since otherwise the
	// synced parent directory would have a dangling entry.
	return os.Mkdir(path, perm)
}

// fsyncDirectory syncs the directory in which the directory entry for path
// resides. Otherwise, after a power failure the file at path may not exist.
// See https://github.com/sqlite/sqlite/blob/024818be2/src/os_unix.c#L3739-L3799
// for confirmation that operating on a file, then opening the directory and
// calling fsync on it is the correct sequence of operations.
func fsyncDirectory(path string) error {
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = parent.Sync()
	if err1 := parent.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}
