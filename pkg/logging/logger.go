// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package logging

import (
	"github.com/go-logr/logr"
)

type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(err error, msg string, keysAndValues ...interface{})
}

type LogrLogger struct {
	logger logr.Logger
}

// NewLogrLogger creates a new LogrLogger instance that wraps a logr.Logger
func NewLogrLogger(logger logr.Logger) *LogrLogger {
	return &LogrLogger{
		logger: logger,
	}
}

// Info logs an info level message
func (l *LogrLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, keysAndValues...)
}

// Error logs an error level message
func (l *LogrLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	l.logger.Error(err, msg, keysAndValues...)
}
