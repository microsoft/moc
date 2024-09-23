// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package errors

import (
	"errors"
	"os"
	"strings"

	perrors "github.com/pkg/errors"
	"go.uber.org/multierr"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	moccodes "github.com/microsoft/moc/pkg/errors/codes"
	"github.com/microsoft/moc/rpc/common"
)

// MocError is a trivial implementation of error that wraps the moc rpc Error struct.
type MocError struct {
	// None of MocError's fields should be modifiable after instantiation
	// since errors are supposed to be immutable.
	err *common.Error
}

func (e *MocError) Error() string {
	return e.err.Message
}

// GetMocCode returns the underlying MocCode of the MocError.
func (e *MocError) GetMocCode() moccodes.MocCode {
	return moccodes.Convert(e.err.Code)
}

// NewMocError creates a new MocError based on the given MocCode.
func NewMocError(code moccodes.MocCode) error {
	return &MocError{
		err: &common.Error{
			Code:    int32(code),
			Message: code.String(),
		},
	}
}

// NewMocErrorWithError creates a new MocError based on the given moc.rpc.common.Error.
// Will return nil if the input error is nil or if the input error has an OK code and an empty message.
// If the input error has an OK code but a non-empty message, it will return an Unknown error code.
// Otherwise it will return an error with the same code and message as the input error.
func NewMocErrorWithError(err *common.Error) error {
	if err == nil {
		return nil
	}

	if err.Code == int32(moccodes.OK) && err.Message == "" {
		// Don't need to return an error if all relevant fields are empty.
		return nil
	}

	if err.Code == int32(moccodes.OK) {
		// If the code is OK, but the message is not, then we should return an Unknown error code.
		// This is to maintain backwards compatibility with older versions of the agent (that autofill an empty code).
		err.Code = int32(moccodes.Unknown)
	}

	return &MocError{
		err: err,
	}
}

var (
	NotFound                    error = NewMocError(moccodes.NotFound)
	Degraded                    error = NewMocError(moccodes.Degraded)
	InvalidConfiguration        error = NewMocError(moccodes.InvalidConfiguration)
	InvalidInput                error = NewMocError(moccodes.InvalidInput)
	InvalidType                 error = NewMocError(moccodes.InvalidType)
	NotSupported                error = NewMocError(moccodes.NotSupported)
	AlreadyExists               error = NewMocError(moccodes.AlreadyExists)
	InUse                       error = NewMocError(moccodes.InUse)
	Duplicates                  error = NewMocError(moccodes.Duplicates)
	InvalidFilter               error = NewMocError(moccodes.InvalidFilter)
	Failed                      error = NewMocError(moccodes.Failed)
	InvalidGroup                error = NewMocError(moccodes.InvalidGroup)
	InvalidVersion              error = NewMocError(moccodes.InvalidVersion)
	OldVersion                  error = NewMocError(moccodes.OldVersion)
	OutOfCapacity               error = NewMocError(moccodes.OutOfCapacity)
	OutOfNodeCapacity           error = NewMocError(moccodes.OutOfNodeCapacity)
	OutOfMemory                 error = NewMocError(moccodes.OutOfMemory)
	UpdateFailed                error = NewMocError(moccodes.UpdateFailed)
	NotInitialized              error = NewMocError(moccodes.NotInitialized)
	NotImplemented              error = NewMocError(moccodes.NotImplemented)
	OutOfRange                  error = NewMocError(moccodes.OutOfRange)
	AlreadySet                  error = NewMocError(moccodes.AlreadySet)
	NotSet                      error = NewMocError(moccodes.NotSet)
	InconsistentState           error = NewMocError(moccodes.InconsistentState)
	PendingState                error = NewMocError(moccodes.PendingState)
	WrongHost                   error = NewMocError(moccodes.WrongHost)
	PoolFull                    error = NewMocError(moccodes.PoolFull)
	NoActionTaken               error = NewMocError(moccodes.NoActionTaken)
	Expired                     error = NewMocError(moccodes.Expired)
	Revoked                     error = NewMocError(moccodes.Revoked)
	Timeout                     error = NewMocError(moccodes.Timeout)
	RunCommandFailed            error = NewMocError(moccodes.RunCommandFailed)
	InvalidToken                error = NewMocError(moccodes.InvalidToken)
	Unknown                     error = NewMocError(moccodes.Unknown)
	DeleteFailed                error = NewMocError(moccodes.DeleteFailed)
	DeletePending               error = NewMocError(moccodes.DeletePending)
	FileNotFound                error = NewMocError(moccodes.FileNotFound)
	PathNotFound                error = NewMocError(moccodes.PathNotFound)
	NotEnoughSpace              error = NewMocError(moccodes.NotEnoughSpace)
	AccessDenied                error = NewMocError(moccodes.AccessDenied)
	BlobNotFound                error = NewMocError(moccodes.BlobNotFound)
	GenericFailure              error = NewMocError(moccodes.GenericFailure)
	NoAuthenticationInformation error = NewMocError(moccodes.NoAuthenticationInformation)
	MeasurementUnitError        error = NewMocError(moccodes.MeasurementUnitError)
	QuotaViolation              error = NewMocError(moccodes.QuotaViolation)
	IPOutOfRange                error = NewMocError(moccodes.IPOutOfRange)
	MultipleErrors              error = NewMocError(moccodes.MultipleErrors)
)

// GetMocErrorCode attempts to extract the MocCode from the given error. If the error is a multierr,
// it will return the MocCode if all errors in the multierr match the same MocCode. If there are
// multiple non-matching MocCodes, then it returns MocCode.MultipleErrors and false.
//
// GetMocErrorCode follows the following rules when parsing individual errors:
//
//   - If the error is nil, it returns MocCode.OK and true.
//   - If the error is of type MocError, it returns the MocCode and true.
//   - If the error has a Cause that is not nil and is of type MocError, it returns the MocCode of the Cause and true.
//   - If both the error and its Cause are not of type MocError, it returns MocCode.Unknown and false.
func GetMocErrorCode(err error) (moccodes.MocCode, bool) {
	errors := multierr.Errors(err)
	if len(errors) == 0 {
		return moccodes.OK, true
	}

	firstMocCode, ok := getSingleMocErrorCode(errors[0])
	if !ok && len(errors) == 1 {
		return moccodes.Unknown, false
	}

	for _, e := range errors[1:] {
		mocCode, ok := getSingleMocErrorCode(e)
		if !ok || mocCode != firstMocCode {
			return moccodes.MultipleErrors, false
		}
	}

	return firstMocCode, true
}

func getSingleMocErrorCode(err error) (moccodes.MocCode, bool) {
	if err == nil {
		return moccodes.OK, true
	}

	// Check if the error itself is a MocError
	if mocErr, ok := err.(*MocError); ok {
		return mocErr.GetMocCode(), true
	}

	// Get the cause of the error
	cerr := perrors.Cause(err)
	if cerr == nil || cerr == err {
		return moccodes.Unknown, false
	}

	// Check if the cause of the error is a MocError
	if mocErr, ok := cerr.(*MocError); ok {
		return mocErr.GetMocCode(), true
	}

	return moccodes.Unknown, false
}

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
	} else if IsIPOutOfRange(err) {
		return "IPOutOfRange"
	} else if IsMultipleErrors(err) {
		return "MultipleErrors"
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

// IsMocErrorCode wraps a call to GetMocErrorCode. It returns true only
// if the error has the same MocCode as the given code (no string matching).
func IsMocErrorCode(err error, code moccodes.MocCode) bool {
	mocCode, _ := GetMocErrorCode(err)
	return mocCode == code
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

func IsIPOutOfRange(err error) bool {
	return checkError(err, IPOutOfRange)
}

func IsMultipleErrors(err error) bool {
	return checkError(err, MultipleErrors)
}

// checkError checks if the wrappedError has the same MocCode as the err error according to GetMocErrorCode.
// If the error is not matched by GetMocErrorCode and the error does not have a GRPC code (or is a GRPC Unknown code),
// it will attempt to match the error strings through string matching (even for multierrors).
func checkError(wrappedError, err error) bool {
	if wrappedError == nil {
		return false
	}
	if wrappedError == err {
		return true
	}
	moccode, ok := GetMocErrorCode(wrappedError)
	errCode, ok2 := GetMocErrorCode(err)
	if ok && ok2 && moccode == errCode {
		return true
	}

	// Ideally, we wouldn't rely on any string matching to identify errors,
	// but we need backwards compatibility. Note this triggers on all errors
	// that don't have GRPC codes.
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
