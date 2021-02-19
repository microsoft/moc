// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func init() {
	os.MkdirAll("/tmp/auth", os.ModePerm)
}

func Test_GetWssdConfigLocationName(t *testing.T) {
	path := GetMocConfigLocationName("", "")
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed getting home path %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd/cloudconfig")
	if path != expectedPath {
		t.Errorf("Invalid path when not passed no subfolder or filename Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetWssdConfigLocationNameWithSubfolder(t *testing.T) {
	path := GetMocConfigLocationName("test", "")
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed getting home path %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd/test/cloudconfig")
	if path != expectedPath {
		t.Errorf("Invalid path when not passed no subfolder or filename Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetWssdConfigLocationNameWithSubfolderName(t *testing.T) {
	path := GetMocConfigLocationName("test", "cc")
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed getting home path %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd/test/cc")
	if path != expectedPath {
		t.Errorf("Invalid path when not passed no subfolder or filename Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetWssdConfigLocationNameWithName(t *testing.T) {
	path := GetMocConfigLocationName("", "cc")
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed getting home path %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd/cc")
	if path != expectedPath {
		t.Errorf("Invalid path when not passed no subfolder or filename Expected %s Actual %s", expectedPath, path)
	}
}
