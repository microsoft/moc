// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package fs

import (
	"os"
	"os/exec"

	"github.com/hectane/go-acl"
)

func Chmod(path string, mode os.FileMode) error {
	return acl.Chmod(path, mode)
}

func ChmodRecursiveAdmin(path string) error {
	// Step1: Remove inhereted permissions
	cmd := exec.Command("icacls", path, "/inheritance:r")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	// Step2: Grant admin permission to the directory
	cmd = exec.Command("icacls", path, "/grant", "BUILTIN\\Administrators:(OI)(CI)(F)")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}
