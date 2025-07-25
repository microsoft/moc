// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package fs

import (
	"os"
	"os/exec"
	"strings"

	"github.com/hectane/go-acl"
	"github.com/microsoft/moc-pkg/pkg/powershell"
	"github.com/microsoft/moc/pkg/errors"
)

func Chmod(path string, mode os.FileMode) error {
	return acl.Chmod(path, mode)
}

func ChmodRecursiveAdmin(path string) error {
	// Step 0: check for command injections because we using exec command to run icacls
	var err error
	if strings.Contains(path, "&") || strings.Contains(path, "|") || strings.Contains(path, ";") || strings.Contains(path, "^") || strings.Contains(path, ">") {
		err = errors.Wrapf(errors.InvalidInput, "Path [%s] contains invalid operators like '&', '|', ';', '^', '>'", path)
		return err
	}

	// Step 1: Remove inhereted permissions
	cmd := exec.Command("icacls", path, "/inheritance:r")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	// Step 2: Grant admin permission to the directory
	getBuiltInAdminGroupName := `function Get-BuiltInAdminName {
	param()
	$obj = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
	$name = ($obj.Translate([System.Security.Principal.NTAccount])).Value
	"$name"
	}
`
	builtInAdminGroupName, err := powershell.ExecutePowershell(getBuiltInAdminGroupName, `Get-BuiltInAdminName`)
	builtInAdminGroupNamePermissions := strings.TrimSpace(builtInAdminGroupName) + ":(OI)(CI)(F)"

	cmd = exec.Command("icacls", path, "/grant", builtInAdminGroupNamePermissions)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}
