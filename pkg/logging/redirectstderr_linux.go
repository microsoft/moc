// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

//+build unix
package logging

import (
	"os"
	"syscall"
)

func RedirectStdErr(file *os.File) {
	err := syscall.Dup2(int(file.Fd()), int(os.Stderr.Fd()))
	if err != nil {
	}
	return
}
