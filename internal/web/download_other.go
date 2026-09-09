//go:build !linux

package web

import "os"

func pseudoFilesystem(*os.File) bool { return false }
