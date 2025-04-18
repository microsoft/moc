// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package auth

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	ClientTokenName       = ".token"
	ClientCertName        = "wssd.pem"
	ClientTokenPath       = "WSSD_CLIENT_TOKEN"
	WssdConfigPath        = "WSSD_CONFIG_PATH"
	AccessFileDirPath     = "ACCESSFILE_DIR_PATH"
	DefaultWSSDFolder     = ".wssd"
	AccessFileDefaultName = "cloudconfig"
)

func getExecutableName() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(filepath.Base(execPath), filepath.Ext(execPath)), nil
}

// SetCertificateDirPath sets the directory path where the client certificate will be stored
// This is achieved by setting ACCESSFILE_DIR_PATH environment variable
// The path is appended with the executable name before the certificate is stored
func SetCertificateDirPath(certificateDirPath string) error {
	return os.Setenv(AccessFileDirPath, certificateDirPath)
}

// SetCertificateFilePath sets the file path where the client certificate will be stored
// This is achieved by setting WSSD_CONFIG_PATH environment variable
func SetCertificateFilePath(certificateFilePath string) error {
	return os.Setenv(WssdConfigPath, certificateFilePath)
}

// SetLoginTokenPath sets the path where the login yaml will be stored
// This is achieved by setting WSSD_CLIENT_TOKEN environment variable
// The path is appended with the executable name before the certificate is stored
func SetLoginTokenPath(loginConfigPath string) error {
	return os.Setenv(ClientTokenPath, loginConfigPath)
}

// GetCertificateDirPath will return the directory path where the client certificate will be stored
func GetCertificateDirPath() string {
	return os.Getenv(AccessFileDirPath)
}

// GetCertificateFilePath will return the file path where the client certificate will be stored
func GetCertificateFilePath() string {
	return os.Getenv(WssdConfigPath)
}

// GetLoginTokenPath will return the file path where the login yaml will be stored
func GetLoginTokenPath() string {
	return os.Getenv(ClientTokenPath)
}

// GetWssdConfigLocation gets the path for access file from environment
func GetWssdConfigLocation() string {
	accessFileDirPath := os.Getenv(AccessFileDirPath)
	wssdConfigPath := os.Getenv(WssdConfigPath)
	defaultPath := accessFileDirPath

	if accessFileDirPath == "" && wssdConfigPath != "" {
		return wssdConfigPath
	}

	if accessFileDirPath == "" && wssdConfigPath == "" {
		wd, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		// Create the default config path and set the
		// env variable
		defaultPath = filepath.Join(wd, DefaultWSSDFolder)
		os.Setenv(AccessFileDirPath, defaultPath)
	}

	if execName, err := getExecutableName(); err == nil {
		defaultPath = filepath.Join(defaultPath, execName)
	}
	os.MkdirAll(defaultPath, os.ModePerm) //nolint:golint,errcheck
	accessFilePath := filepath.Join(defaultPath, AccessFileDefaultName)
	return accessFilePath
}

// GetWssdConfigLocationName gets the path for access filename from environment + subfolder with file name fileName
func GetMocConfigLocationName(subfolder, filename string) string {
	wssdConfigPath := os.Getenv(WssdConfigPath)

	file := AccessFileDefaultName
	if filename != "" {
		file = filename
	}
	wd, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	if wssdConfigPath == "" || !strings.HasSuffix(wssdConfigPath, filepath.Join(wd, subfolder, file)) {
		// Create the default config path and set the
		// env variable
		defaultPath := filepath.Join(wd, DefaultWSSDFolder, subfolder)
		os.MkdirAll(defaultPath, os.ModePerm) //nolint:golint,errcheck
		wssdConfigPath = filepath.Join(defaultPath, file)
		os.Setenv(WssdConfigPath, wssdConfigPath)
	}
	return wssdConfigPath
}

func getClientTokenLocation() string {
	clientTokenPath := os.Getenv(ClientTokenPath)
	if clientTokenPath == "" {
		wd, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		// Create the default token path and set the
		// env variable
		defaultPath := filepath.Join(wd, DefaultWSSDFolder)
		os.MkdirAll(defaultPath, os.ModePerm)
		clientTokenPath = filepath.Join(defaultPath, ClientTokenName)
		os.Setenv(ClientTokenPath, clientTokenPath)
	}
	return clientTokenPath
}
