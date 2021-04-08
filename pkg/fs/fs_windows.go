// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package fs

import (
	"os"

	"github.com/hectane/go-acl"
)

func Chmod(path string, mode os.FileMode) error {
	return acl.Chmod(path, mode)
}
