// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

//go:build darwin

package logging

import (
	"os"
	"syscall"
)

func RedirectStdErr(file *os.File) {
	syscall.Dup2(int(file.Fd()), int(os.Stderr.Fd())) //nolint:golint,errcheck
}
