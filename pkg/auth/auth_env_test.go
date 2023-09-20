// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
)

var key *rsa.PrivateKey

func init() {
	os.MkdirAll("/tmp/auth", os.ModePerm)
	key, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func Test_GetWssdConfigLocationWssdConfigPathSet(t *testing.T) {

	os.Unsetenv(AccessFileDirPath)
	os.Setenv(WssdConfigPath, "TestWssdConfigPath")

	wssdConfigPath := os.Getenv(WssdConfigPath)
	path := GetWssdConfigLocation()
	expectedPath := wssdConfigPath
	if path != expectedPath {
		t.Errorf("Invalid path when ACCESSFILE_DIR_PATH is not set and WSSD_CONFIG_PATH is set! Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetWssdConfigLocationEnvNotSet(t *testing.T) {

	os.Unsetenv(WssdConfigPath)
	os.Unsetenv(AccessFileDirPath)

	path := GetWssdConfigLocation()
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed to get user home directory path %v", err)
	}
	execName, err := getExecutableName()
	if err != nil {
		t.Errorf("Failed to get executable name %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd", execName, "cloudconfig")
	if path != expectedPath {
		t.Errorf("Invalid path when both ACCESSFILE_DIR_PATH and WSSD_CONFIG_PATH env variables are not set! Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetWssdConfigLocationAccessFileDirPathSet(t *testing.T) {

	os.Setenv(AccessFileDirPath, "TestAccessFileDirPath")
	accessFileDirPath := os.Getenv(AccessFileDirPath)
	path := GetWssdConfigLocation()
	execName, err := getExecutableName()
	if err != nil {
		t.Errorf("Failed to get executable name %v", err)
	}
	expectedPath := filepath.Join(accessFileDirPath, execName, "cloudconfig")
	if path != expectedPath {
		t.Errorf("Invalid path when ACCESSFILE_DIR_PATH env variable is set! Expected %s Actual %s", expectedPath, path)
	}
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
