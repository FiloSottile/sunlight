//go:build !linux

package ctlog

func onZFS(_ string) bool { return false }
