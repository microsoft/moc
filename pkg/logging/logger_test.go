package logging

import (
	"errors"
	"testing"

	"github.com/go-logr/logr/testr"
)

func TestLogrLogger_Info(t *testing.T) {
	testLogr := testr.New(t)
	logrLogger := NewLogrLogger(testLogr)

	logrLogger.Info("test info message", "key1", "value1", "key2", 123)
}

func TestLogrLogger_Error(t *testing.T) {
	testLogr := testr.New(t)
	logrLogger := NewLogrLogger(testLogr)

	err := errors.New("test error")
	logrLogger.Error(err, "test error message", "key3", true, "key4", 456.78)
}
