// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

// Package loggingRedirect - Creates a log file the redirects STD output.
package logging

import (
	"log"
	"os"
	"path/filepath"

	path "github.com/microsoft/moc/pkg/path"
)

var (
	oldStdOut *os.File
	oldStdErr *os.File
	logFile   *os.File
)

func createLogFile(logFileAbsolutePath string, logFileName string) (*os.File, error) {
	// Create log path
	os.MkdirAll(logFileAbsolutePath, os.ModeDir) //nolint:golint,errcheck

	err := path.CheckPath(logFileAbsolutePath)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(logFileAbsolutePath, logFileName)
	logFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	st, err := logFile.Stat()
	if err != nil {
		return nil, err
	}

	// If there are contents in the file already, move the file and replace it.
	if st.Size() > 0 {
		logFile.Close()
		os.Rename(path, path+".old") //nolint:golint,errcheck
		logFile, err = os.Create(path)
		if err != nil {
			return nil, err
		}
	}

	return logFile, nil
}

// StartRedirectingOutput
func StartRedirectingOutput(logFileAbsolutePath string, logFileName string) error {
	// Save previous values
	oldStdOut = os.Stdout
	oldStdErr = os.Stderr

	// Create output file
	var err error
	logFile, err = createLogFile(logFileAbsolutePath, logFileName)
	if err != nil {
		return err
	}

	RedirectStdErr(logFile)
	// Set output to file
	os.Stdout = logFile
	log.SetOutput(logFile)

	return nil
}

// RestoreOutput
func RestoreOutput() {
	// Restoring previous values
	os.Stdout = oldStdOut
	os.Stderr = oldStdErr
	log.SetOutput(os.Stderr)

	if logFile != nil {
		// Close log file
		logFile.Close()
		logFile = nil
	}
}
