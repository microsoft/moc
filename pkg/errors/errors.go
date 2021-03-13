// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package errors

import (
	"errors"
	"strings"

	perrors "github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

var (
	NotFound             error = errors.New("Not Found")
	Degraded             error = errors.New("Degraded")
	InvalidConfiguration error = errors.New("Invalid Configuration")
	InvalidInput         error = errors.New("Invalid Input")
	NotSupported         error = errors.New("Not Supported")
	AlreadyExists        error = errors.New("Already Exists")
	InUse                error = errors.New("In Use")
	Duplicates           error = errors.New("Duplicates")
	InvalidFilter        error = errors.New("Invalid Filter")
	Failed               error = errors.New("Failed")
	InvalidGroup         error = errors.New("InvalidGroup")
	InvalidVersion       error = errors.New("InvalidVersion")
	OldVersion           error = errors.New("OldVersion")
	OutOfCapacity        error = errors.New("OutOfCapacity")
	OutOfMemory          error = errors.New("OutOfMemory")
	UpdateFailed         error = errors.New("Update Failed")
	NotInitialized       error = errors.New("Not Initialized")
	NotImplemented       error = errors.New("Not Implemented")
	OutOfRange           error = errors.New("Out of range")
	AlreadySet           error = errors.New("Already Set")
	NotSet               error = errors.New("Not Set")
	InconsistentState    error = errors.New("Inconsistent state")
	PendingState         error = errors.New("Pending state")
	WrongHost            error = errors.New("Wrong host")
	PoolFull             error = errors.New("The pool is full")
	NoActionTaken        error = errors.New("No Action Taken")
	Expired              error = errors.New("Expired")
	Revoked              error = errors.New("Revoked")
	Timeout              error = errors.New("The operation has timed out")
	Unknown              error = errors.New("Unknown Reason")
)

func GetErrorCode(err error) string {
	if IsNotFound(err) {
		return "NotFound"
	} else if IsDegraded(err) {
		return "Degraded"
	} else if IsInvalidConfiguration(err) {
		return "InvalidConfiguration"
	} else if IsInvalidInput(err) {
		return "InvalidInput"
	} else if IsNotSupported(err) {
		return "NotSupported"
	} else if IsAlreadyExists(err) {
		return "AlreadyExists"
	} else if IsInUse(err) {
		return "InUse"
	} else if IsDuplicates(err) {
		return "Duplicates"
	} else if IsInvalidFilter(err) {
		return "InvalidFilter"
	} else if IsFailed(err) {
		return "Failed"
	} else if IsInvalidGroup(err) {
		return "InvalidGroup"
	} else if IsInvalidVersion(err) {
		return "InvalidVersion"
	} else if IsOldVersion(err) {
		return "OldVersion"
	} else if IsOutOfCapacity(err) {
		return "OutOfCapacity"
	} else if IsOutOfMemory(err) {
		return "OutOfMemory"
	} else if IsUpdateFailed(err) {
		return "UpdateFailed"
	} else if IsNotInitialized(err) {
		return "NotInitialized"
	} else if IsNotImplemented(err) {
		return "NotImplemented"
	} else if IsOutOfRange(err) {
		return "OutOfRange"
	} else if IsAlreadySet(err) {
		return "AlreadySet"
	} else if IsNotSet(err) {
		return "NotSet"
	} else if IsInconsistentState(err) {
		return "InconsistentState"
	} else if IsPendingState(err) {
		return "PendingState"
	} else if IsWrongHost(err) {
		return "WrongHost"
	} else if IsPoolFull(err) {
		return "PoolFull"
	} else if IsNoActionTaken(err) {
		return "NoActionTaken"
	} else if IsExpired(err) {
		return "Expired"
	} else if IsRevoked(err) {
		return "Revoked"
	} else if IsTimeout(err) {
		return "Timeout"
	} else if IsUnknown(err) {
		return "Unknown"
	}

	return "GenericError"
}

func Wrap(cause error, message string) error {
	return perrors.Wrap(cause, message)
}

func Wrapf(err error, format string, args ...interface{}) error {
	return perrors.Wrapf(err, format, args...)
}

func GetGRPCErrorCode(err error) codes.Code {
	if derr, ok := status.FromError(err); ok {
		return derr.Code()
	}
	return codes.Unknown
}

func checkGRPCErrorCode(err error, code codes.Code) bool {
	if derr, ok := status.FromError(err); ok {
		return derr.Code() == code
	}
	return status.Code(err) == code
}

func IsGRPCUnknown(err error) bool {
	return checkGRPCErrorCode(err, codes.Unknown)
}

func IsGRPCNotFound(err error) bool {
	return checkGRPCErrorCode(err, codes.NotFound)
}

func IsGRPCDeadlineExceeded(err error) bool {
	return checkGRPCErrorCode(err, codes.DeadlineExceeded)
}

func IsGRPCAlreadyExist(err error) bool {
	return checkGRPCErrorCode(err, codes.AlreadyExists)
}

func IsGRPCUnavailable(err error) bool {
	return checkGRPCErrorCode(err, codes.Unavailable)
}

func IsGRPCAborted(err error) bool {
	return checkGRPCErrorCode(err, codes.Aborted)
}

func GetGRPCError(err error) error {
	if err == nil {
		return err
	}
	if IsNotFound(err) {
		return status.Errorf(codes.NotFound, err.Error())
	}
	if IsAlreadyExists(err) {
		return status.Errorf(codes.AlreadyExists, err.Error())
	}
	return err
}

func IsOutOfMemory(err error) bool {
	return checkError(err, OutOfMemory)
}
func IsInvalidVersion(err error) bool {
	return checkError(err, InvalidVersion)
}
func IsNotFound(err error) bool {
	return checkError(err, NotFound)
}
func IsDegraded(err error) bool {
	return checkError(err, Degraded)
}
func IsNotSupported(err error) bool {
	return checkError(err, NotSupported)
}
func IsInvalidConfiguration(err error) bool {
	return checkError(err, InvalidConfiguration)
}
func IsInvalidInput(err error) bool {
	return checkError(err, InvalidInput)
}
func IsAlreadyExists(err error) bool {
	return checkError(err, AlreadyExists)
}
func IsInvalidGroup(err error) bool {
	return checkError(err, InvalidGroup)
}
func IsNotInitialized(err error) bool {
	return checkError(err, NotInitialized)
}
func IsOutOfRange(err error) bool {
	return checkError(err, OutOfRange)
}
func IsOutOfCapacity(err error) bool {
	return checkError(err, OutOfCapacity)
}
func IsAlreadySet(err error) bool {
	return checkError(err, AlreadySet)
}
func IsNotSet(err error) bool {
	return checkError(err, NotSet)
}
func IsInconsistentState(err error) bool {
	return checkError(err, InconsistentState)
}
func IsPendingState(err error) bool {
	return checkError(err, PendingState)
}
func IsInUse(err error) bool {
	return checkError(err, InUse)
}
func IsDuplicates(err error) bool {
	return checkError(err, Duplicates)
}
func IsInvalidFilter(err error) bool {
	return checkError(err, InvalidFilter)
}
func IsFailed(err error) bool {
	return checkError(err, Failed)
}
func IsOldVersion(err error) bool {
	return checkError(err, OldVersion)
}
func IsUpdateFailed(err error) bool {
	return checkError(err, UpdateFailed)
}
func IsNotImplemented(err error) bool {
	return checkError(err, NotImplemented)
}
func IsUnknown(err error) bool {
	return checkError(err, Unknown)
}
func IsWrongHost(err error) bool {
	return checkError(err, WrongHost)
}
func IsPoolFull(err error) bool {
	return checkError(err, PoolFull)
}
func IsNoActionTaken(err error) bool {
	return checkError(err, NoActionTaken)
}
func IsExpired(err error) bool {
	return checkError(err, Expired)
}
func IsRevoked(err error) bool {
	return checkError(err, Revoked)
}
func IsTimeout(err error) bool {
	return checkError(err, Timeout)
}

func checkError(wrappedError, err error) bool {
	if wrappedError == nil {
		return false
	}
	if wrappedError == err {
		return true
	}
	cerr := perrors.Cause(wrappedError)
	if cerr != nil && cerr == err {
		return true
	}

	if !IsGRPCUnknown(err) {
		return false
	}

	// Post this, this is a GRPC unknown error
	// Try to parse the Message and match the error
	if strings.Contains(wrappedError.Error(), err.Error()) {
		return true
	}

	return false

}

func New(errString string) error {
	return errors.New(errString)
}
