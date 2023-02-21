// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

//+build windows
package logging

import (
	"os"
	"syscall"
)

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	procSetStdHandle = kernel32.MustFindProc("SetStdHandle")
)

func setStdHandle(stdhandle int32, handle syscall.Handle) error {
	r0, _, e1 := syscall.Syscall(procSetStdHandle.Addr(), 2, uintptr(stdhandle), uintptr(handle), 0)
	if r0 == 0 {
		if e1 != 0 {
			return error(e1)
		}
		return syscall.EINVAL
	}
	return nil
}

func RedirectStdErr(file *os.File) {
	err := setStdHandle(syscall.STD_ERROR_HANDLE, syscall.Handle(file.Fd()))
	if err != nil {
	}
	os.Stderr = file
	return
}
