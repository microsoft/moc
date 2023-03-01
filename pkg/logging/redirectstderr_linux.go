// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

//go:build unix
// +build unix

package logging

import (
	"os"
	"syscall"
)

func RedirectStdErr(file *os.File) {
	err := syscall.Dup3(int(file.Fd()), int(os.Stderr.Fd()), 0)
	if err != nil {
	}
	return
}
