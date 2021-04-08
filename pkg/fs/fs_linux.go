// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package fs

import (
	"os"
)

func Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}
