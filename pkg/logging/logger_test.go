package logging

import (
	"bytes"
	"errors"
	"github.com/stretchr/testify/assert"
	"os"
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

func TestDefaultLogger_Info(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := &DefaultLogger{}
	logger.Info("test info message", "key1", "value1", "key2", 123)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	expectedOutput := "INFO: test info message key1 value1 key2 123\n"
	assert.Equal(t, expectedOutput, output)
}

func TestDefaultLogger_Error(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := &DefaultLogger{}
	err := errors.New("test error")
	logger.Error(err, "test error message", "key3", true, "key4", 456.78)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	expectedOutput := "ERROR: test error message key3 true key4 456.78\nError: test error\n"
	assert.Equal(t, expectedOutput, output)
}
