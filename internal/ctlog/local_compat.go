//go:build !linux || (!amd64 && !arm64)

package ctlog

func setImmutable(name string)   {}
func unsetImmutable(name string) {}
