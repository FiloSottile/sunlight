// Package durable provides equivalent functionality to the os package, but with
// additional guarantees for durability based on [os.File.Sync].
//
// See https://wiki.postgresql.org/wiki/Fsync_Errors for a discussion of the
// reliability of fsync.
package durable

import (
	"os"
	"path/filepath"
	"syscall"
)

// WriteFile behaves like [os.WriteFile], but it also syncs the file contents
// and the directory containing the file to disk.
func WriteFile(name string, data []byte, perm os.FileMode) (err error) {
	// After the file, sync the directory in which the entry resides. Otherwise,
	// after a power failure the file may not exist.
	//
	// Keep the parent open during the operation, to prevent it from being
	// evicted from the inode cache, which can discard a write-through error.
	//
	// Note that this is not necessary if the file already exists. Our use of
	// this function is mostly for creating new files, so we don't optimize for
	// the case where the file already exists.
	parent, err := os.Open(filepath.Dir(name))
	if err != nil {
		return &os.PathError{Op: "write", Path: name, Err: err}
	}
	defer fsyncAndClose(parent, &err)

	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
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

// Mkdir behaves like [os.Mkdir], but it also syncs the directory containing
// the created directory to disk.
func Mkdir(path string, perm os.FileMode) (err error) {
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	defer fsyncAndClose(parent, &err)

	if err := os.Mkdir(path, perm); err != nil {
		return err
	}

	f, err := os.Open(path)
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
