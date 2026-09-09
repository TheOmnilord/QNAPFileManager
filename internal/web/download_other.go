//go:build !linux

package web

import "os"

func prepareDownloadStream(f *os.File) (*os.File, error) { return f, nil }

func pseudoFilesystem(*os.File) bool { return false }
