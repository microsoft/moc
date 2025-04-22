// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package logging

import (
	"os"
	"syscall"
)

func RedirectStdErr(file *os.File) {
	syscall.Dup3(int(file.Fd()), int(os.Stderr.Fd()), 0) //nolint:golint,errcheck
	return
}
