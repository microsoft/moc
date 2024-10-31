// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package fs

import (
	"os"
	"path/filepath"
)

func Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

func ChmodRecursiveAdmin(path string) error {
	err := filepath.Walk(path, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if walkErr = Chmod(path, 0700); walkErr != nil {
			return walkErr
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
