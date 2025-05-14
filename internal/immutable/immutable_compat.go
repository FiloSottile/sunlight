//go:build !linux || (!amd64 && !arm64)

package immutable

import "os"

func Set(*os.File)   {}
func Unset(*os.File) {}
