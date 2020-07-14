// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

// Package path has code for working with windows paths.
package path

import (
	"fmt"
	"os"
	"path/filepath"
)

// CheckPath verifies that the path provided exists and returns the absolute path.
func CheckPath(path string) error {
	cleanPath := filepath.Clean(path)
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return err
	}
	if !fileInfo.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}
