// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package fs

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/hectane/go-acl"
	"github.com/microsoft/moc/pkg/errors"
)

func executePowershellCommand(powershellCommand string) (outputJson string, err error) {
	cmd := exec.Command("powershell.exe", powershellCommand)
	var out bytes.Buffer
	cmd.Stdout = &out
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	err = cmd.Run()

	if err != nil {
		return "", errors.Wrapf(err, "executePowershell failed with error %s", errBuf.String())
	}

	return out.String(), nil
}

// Copy of ExecutePowershell function in moc-pkg. This is a temporary workaround till a permanent solution is finalized
func mocExecutePowershell(script string, command string, args ...interface{}) (outputJson string, err error) {
	powershellCommand := script
	powershellCommand += fmt.Sprintf(command, args...)
	log.Printf("ExecutePowershell [%s]\n", powershellCommand)
	outputJson, err = executePowershellCommand(powershellCommand)
	if err != nil {
		return "", err
	}

	log.Printf("Result [%s]\n", outputJson)
	return outputJson, nil
}

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
	builtInAdminGroupName, err := mocExecutePowershell(getBuiltInAdminGroupName, `Get-BuiltInAdminName`)
	if err != nil {
		return err
	}
	builtInAdminGroupNamePermissions := strings.TrimSpace(builtInAdminGroupName) + ":(OI)(CI)(F)"

	cmd = exec.Command("icacls", path, "/grant", builtInAdminGroupNamePermissions)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}
