// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package logging

import (
	"context"
	"io"
	"os"
)

const BUFFER_SIZE = 1024

func UploadFile(ctx context.Context, filename string, sendFunc func([]byte, error) error) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	err = upload(ctx, f, sendFunc)
	if err != io.EOF {
		return err
	}
	return nil
}

func upload(ctx context.Context, reader io.Reader, sendFunc func([]byte, error) error) error {
	var err error
	for err == nil {
		buffer := make([]byte, BUFFER_SIZE)
		_, readErr := reader.Read(buffer)

		err = sendFunc(buffer, readErr)
	}
	return err
}

func Forward(ctx context.Context, sendFunc func([]byte, error) error, recFunc func() ([]byte, error)) error {
	var err error
	for err == nil {
		var buffer []byte
		buffer, readErr := recFunc()

		err = sendFunc(buffer, readErr)
	}
	return err
}

func ReceiveFile(ctx context.Context, filename string, recFunc func() ([]byte, error)) error {
	f, err := os.OpenFile(filename, os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	err = receive(ctx, f, recFunc)
	if err != io.EOF {
		// if hit an actual error then we want to clean up the file
		f.Close()
		os.Remove(filename)
		return err
	}
	defer f.Close()

	return nil
}

func receive(ctx context.Context, writer io.Writer, recFunc func() ([]byte, error)) error {
	var err error
	for err == nil {
		var buffer []byte
		buffer, err = recFunc()

		_, writeErr := writer.Write(buffer)
		if writeErr != nil {
			return writeErr
		}
	}
	return err
}
