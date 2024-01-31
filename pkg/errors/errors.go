// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package errors

import (
	"errors"
	"os"
	"strings"

	perrors "github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

var (
	NotFound                    error = errors.New("Not Found")
	Degraded                    error = errors.New("Degraded")
	InvalidConfiguration        error = errors.New("Invalid Configuration")
	InvalidInput                error = errors.New("Invalid Input")
	InvalidType                 error = errors.New("Invalid Type")
	NotSupported                error = errors.New("Not Supported")
	AlreadyExists               error = errors.New("Already Exists")
	InUse                       error = errors.New("In Use")
	Duplicates                  error = errors.New("Duplicates")
	InvalidFilter               error = errors.New("Invalid Filter")
	Failed                      error = errors.New("Failed")
	InvalidGroup                error = errors.New("InvalidGroup")
	InvalidVersion              error = errors.New("InvalidVersion")
	OldVersion                  error = errors.New("OldVersion")
	OutOfCapacity               error = errors.New("OutOfCapacity")
	OutOfNodeCapacity           error = errors.New("OutOfNodeCapacity")
	OutOfMemory                 error = errors.New("OutOfMemory")
	UpdateFailed                error = errors.New("Update Failed")
	NotInitialized              error = errors.New("Not Initialized")
	NotImplemented              error = errors.New("Not Implemented")
	OutOfRange                  error = errors.New("Out of range")
	AlreadySet                  error = errors.New("Already Set")
	NotSet                      error = errors.New("Not Set")
	InconsistentState           error = errors.New("Inconsistent state")
	PendingState                error = errors.New("Pending state")
	WrongHost                   error = errors.New("Wrong host")
	PoolFull                    error = errors.New("The pool is full")
	NoActionTaken               error = errors.New("No Action Taken")
	Expired                     error = errors.New("Expired")
	Revoked                     error = errors.New("Revoked")
	Timeout                     error = errors.New("Timedout")
	RunCommandFailed            error = errors.New("Run Command Failed")
	InvalidToken                error = errors.New("InvalidToken")
	Unknown                     error = errors.New("Unknown Reason")
	DeleteFailed                error = errors.New("Delete Failed")
	DeletePending               error = errors.New("Delete Pending")
	FileNotFound                error = errors.New("The system cannot find the file specified")
	PathNotFound                error = errors.New("The system cannot find the path specified")
	NotEnoughSpace              error = errors.New("There is not enough space on the disk")
	AccessDenied                error = errors.New("Access is denied")
	BlobNotFound                error = errors.New("BlobNotFound")
	GenericFailure              error = errors.New("Generic failure")
	NoAuthenticationInformation error = errors.New("NoAuthenticationInformation")
	MeasurementUnitError        error = errors.New("byte quantity must be a positive integer with a unit of measurement like")
	QuotaViolation              error = errors.New("Quota violation")
	IPOutOfRange                error = errors.New("IP is out of range")
)

func GetErrorCode(err error) string {
	if IsNotFound(err) || IsFileNotFound(err) || IsPathNotFound(err) || IsBlobNotFound(err) {
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
	} else if IsInvalidType(err) {
		return "InvalidType"
	} else if IsInvalidVersion(err) {
		return "InvalidVersion"
	} else if IsOldVersion(err) {
		return "OldVersion"
	} else if IsOutOfCapacity(err) || IsNotEnoughSpace(err) {
		return "OutOfCapacity"
	} else if IsOutOfNodeCapacity(err) {
		return "OutOfNodeCapacity"
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
	} else if IsInvalidToken(err) {
		return "InvalidToken"
	} else if IsUnknown(err) || IsGenericFailure(err) {
		return "Unknown"
	} else if IsDeleteFailed(err) {
		return "Delete Failed"
	} else if IsDeletePending(err) {
		return "Delete Pending"
	} else if IsRunCommandFailed(err) {
		return "RunCommandFailed"
	} else if IsAccessDenied(err) {
		return "AccessDenied"
	} else if IsNoAuthenticationInformation(err) {
		return "NoAuthenticationInformation"
	} else if IsQuotaViolation(err) {
		return "QuotaViolation"
	} else if IsMeasurementUnitError(err) {
		return "MeasurementUnitError"
	} else if IPOutOfRange(err) {
		return "IPOutOfRange"
	}

	// We dont know the type of error.
	// Returning the base error string
	return err.Error()
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
func IsInvalidType(err error) bool {
	return checkError(err, InvalidType)
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
func IsOutOfNodeCapacity(err error) bool {
	return checkError(err, OutOfNodeCapacity)
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
func IsInvalidToken(err error) bool {
	return checkError(err, InvalidToken)
}
func IsDeleteFailed(err error) bool {
	return checkError(err, DeleteFailed)
}
func IsDeletePending(err error) bool {
	return checkError(err, DeletePending)
}

func IsErrDeadlineExceeded(err error) bool {
	return checkError(err, os.ErrDeadlineExceeded)
}

func IsRunCommandFailed(err error) bool {
	return checkError(err, RunCommandFailed)
}

func IsFileNotFound(err error) bool {
	return checkError(err, FileNotFound)
}

func IsPathNotFound(err error) bool {
	return checkError(err, PathNotFound)
}

func IsNotEnoughSpace(err error) bool {
	return checkError(err, NotEnoughSpace)
}

func IsAccessDenied(err error) bool {
	return checkError(err, AccessDenied)
}

func IsBlobNotFound(err error) bool {
	return checkError(err, BlobNotFound)
}

func IsGenericFailure(err error) bool {
	return checkError(err, GenericFailure)
}

func IsNoAuthenticationInformation(err error) bool {
	return checkError(err, NoAuthenticationInformation)
}

func IsMeasurementUnitError(err error) bool {
	return checkError(err, MeasurementUnitError)
}

func IsQuotaViolation(err error) bool {
	return checkError(err, QuotaViolation)
}

func IPOutOfRange(err error) bool {
	return checkError(err, IPOutOfRange)
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
	wrappedErrorLowercase := strings.ToLower(wrappedError.Error())
	errLowercase := strings.ToLower(err.Error())
	if strings.Contains(wrappedErrorLowercase, errLowercase) {
		return true
	}

	return false
}

func New(errString string) error {
	return errors.New(errString)
}
