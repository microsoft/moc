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

// MocError is an implementation of error that wraps a MocCode and an error message.
type MocError struct {
	code moccodes.MocCode
	err  string
}

func (e *MocError) Error() string {
	return e.err
}

// GetMocCode returns the underlying MocCode of the MocError.
func (e *MocError) GetMocCode() moccodes.MocCode {
	return e.code
}

// NewMocError creates a new MocError based on the given MocCode and message.
// If code is OK, it will return nil.
func NewMocError(code moccodes.MocCode) error {
	if code == moccodes.OK {
		return nil
	}

	// We need to use the legacy map to maintain backwards compatibility with older versions of moc/pkg/errors.
	msg, isLegacy := legacyErrorMessages[code]
	if !isLegacy {
		msg = code.String()
	}

	return &MocError{
		code: code,
		err:  msg,
	}
}

// ErrorToProto converts an error to a protobuf common.Error by extracting the MocCode and message.
func ErrorToProto(err error) *common.Error {
	if err == nil {
		return &common.Error{}
	}

	return &common.Error{
		Code:    GetMocErrorCode(err).ToUint32(),
		Message: err.Error(), // Use Error() to avoid including stack trace
	}
}

// ProtoToMocError converts a protobuf common.Error to a MocError.
func ProtoToMocError(protoErr *common.Error) error {
	if protoErr == nil {
		return nil
	}

	if protoErr.Code == moccodes.OK.ToUint32() && protoErr.Message == "" {
		// Don't need to return an error if all relevant fields are empty.
		return nil
	}

	if protoErr.Code == moccodes.OK.ToUint32() {
		// If the code is OK, but the message is not, then we should return an Unknown error code.
		// This is to maintain backwards compatibility with older versions of the agent (that autofill an empty code).
		protoErr.Code = moccodes.Unknown.ToUint32()
	}

	return &MocError{
		code: moccodes.Convert(protoErr.GetCode()),
		err:  protoErr.Message,
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
	PreCheckFailed              error = NewMocError(moccodes.PreCheckFailed)
	ProviderNotReady            error = NewMocError(moccodes.ProviderNotReady)
	InconsistentVersion         error = NewMocError(moccodes.InconsistentVersion)
)

// legacyErrorMessages - map of error codes to their legacy string representation. This is solely for backwards compatibility
// for checkError() since it uses strings.contains() to match errors.
var legacyErrorMessages = map[moccodes.MocCode]string{
	moccodes.NotFound:             "Not Found",
	moccodes.InvalidConfiguration: "Invalid Configuration",
	moccodes.InvalidInput:         "Invalid Input",
	moccodes.InvalidType:          "Invalid Type",
	moccodes.NotSupported:         "Not Supported",
	moccodes.AlreadyExists:        "Already Exists",
	moccodes.InUse:                "In Use",
	moccodes.InvalidFilter:        "Invalid Filter",
	moccodes.UpdateFailed:         "Update Failed",
	moccodes.NotInitialized:       "Not Initialized",
	moccodes.NotImplemented:       "Not Implemented",
	moccodes.OutOfRange:           "Out of Range",
	moccodes.AlreadySet:           "Already Set",
	moccodes.NotSet:               "Not Set",
	moccodes.InconsistentState:    "Inconsistent State",
	moccodes.PendingState:         "Pending State",
	moccodes.WrongHost:            "Wrong Host",
	moccodes.PoolFull:             "The pool is full",
	moccodes.NoActionTaken:        "No Action Taken",
	moccodes.Timeout:              "Timed out",
	moccodes.RunCommandFailed:     "Run Command Failed",
	moccodes.Unknown:              "Unknown Reason",
	moccodes.DeleteFailed:         "Delete Failed",
	moccodes.DeletePending:        "Delete Pending",
	moccodes.FileNotFound:         "The system cannot find the file specified",
	moccodes.PathNotFound:         "The system cannot find the path specified",
	moccodes.NotEnoughSpace:       "There is not enough space on the disk",
	moccodes.AccessDenied:         "Access is denied",
	moccodes.GenericFailure:       "Generic Failure",
	moccodes.MeasurementUnitError: "Byte quantity must be a positive integer with a unit of measurement like",
	moccodes.QuotaViolation:       "Quota Violation",
	moccodes.IPOutOfRange:         "IP is out of range",
}

// GetMocErrorCode attempts to extract the MocCode from the given error. If the error is a multierr,
// it will return the MocCode if all errors in the multierr match the same MocCode. Otherwise, it returns
// MocCode.Unknown.
//
// GetMocErrorCode follows the following rules when parsing individual errors:
//
//   - If the error is nil, it returns MocCode.OK.
//   - If the error is of type MocError, it returns the MocCode.
//   - If the error has a Cause that is not nil and is of type MocError, it returns the MocCode of the Cause.
//   - If both the error and its Cause are not of type MocError, it returns MocCode.Unknown.
func GetMocErrorCode(err error) moccodes.MocCode {
	errors := multierr.Errors(err)
	if len(errors) == 0 {
		return moccodes.OK
	}

	firstMocCode := getSingleMocErrorCode(errors[0])
	for _, e := range errors[1:] {
		if mocCode := getSingleMocErrorCode(e); mocCode != firstMocCode {
			return moccodes.Unknown
		}
	}

	return firstMocCode
}

func getSingleMocErrorCode(err error) moccodes.MocCode {
	if err == nil {
		return moccodes.OK
	}

	// Check if the error itself is a MocError
	if mocErr, ok := err.(*MocError); ok {
		return mocErr.GetMocCode()
	}

	// Get the cause of the error
	cerr := perrors.Cause(err)
	if cerr == nil {
		return moccodes.Unknown
	}

	// Check if the cause of the error is a MocError
	if mocErr, ok := cerr.(*MocError); ok {
		return mocErr.GetMocCode()
	}

	return moccodes.Unknown
}

func GetErrorCode(err error) string {
	if IsNotFound(err) || IsFileNotFound(err) || IsPathNotFound(err) || IsBlobNotFound(err) {
		return moccodes.NotFound.String()
	} else if IsDegraded(err) {
		return moccodes.Degraded.String()
	} else if IsInvalidConfiguration(err) {
		return moccodes.InvalidConfiguration.String()
	} else if IsInvalidInput(err) {
		return moccodes.InvalidInput.String()
	} else if IsNotSupported(err) {
		return moccodes.NotSupported.String()
	} else if IsAlreadyExists(err) {
		return moccodes.AlreadyExists.String()
	} else if IsInUse(err) {
		return moccodes.InUse.String()
	} else if IsDuplicates(err) {
		return moccodes.Duplicates.String()
	} else if IsInvalidFilter(err) {
		return moccodes.InvalidFilter.String()
	} else if IsFailed(err) {
		return moccodes.Failed.String()
	} else if IsInvalidGroup(err) {
		return moccodes.InvalidGroup.String()
	} else if IsInvalidType(err) {
		return moccodes.InvalidType.String()
	} else if IsInvalidVersion(err) {
		return moccodes.InvalidVersion.String()
	} else if IsOldVersion(err) {
		return moccodes.OldVersion.String()
	} else if IsOutOfCapacity(err) || IsNotEnoughSpace(err) {
		return moccodes.OutOfCapacity.String()
	} else if IsOutOfNodeCapacity(err) {
		return moccodes.OutOfNodeCapacity.String()
	} else if IsOutOfMemory(err) {
		return moccodes.OutOfMemory.String()
	} else if IsUpdateFailed(err) {
		return moccodes.UpdateFailed.String()
	} else if IsNotInitialized(err) {
		return moccodes.NotInitialized.String()
	} else if IsNotImplemented(err) {
		return moccodes.NotImplemented.String()
	} else if IsOutOfRange(err) {
		return moccodes.OutOfRange.String()
	} else if IsAlreadySet(err) {
		return moccodes.AlreadySet.String()
	} else if IsNotSet(err) {
		return moccodes.NotSet.String()
	} else if IsInconsistentState(err) {
		return moccodes.InconsistentState.String()
	} else if IsPendingState(err) {
		return moccodes.PendingState.String()
	} else if IsWrongHost(err) {
		return moccodes.WrongHost.String()
	} else if IsPoolFull(err) {
		return moccodes.PoolFull.String()
	} else if IsNoActionTaken(err) {
		return moccodes.NoActionTaken.String()
	} else if IsExpired(err) {
		return moccodes.Expired.String()
	} else if IsRevoked(err) {
		return moccodes.Revoked.String()
	} else if IsTimeout(err) {
		return moccodes.Timeout.String()
	} else if IsInvalidToken(err) {
		return moccodes.InvalidToken.String()
	} else if IsUnknown(err) || IsGenericFailure(err) {
		return moccodes.Unknown.String()
	} else if IsDeleteFailed(err) {
		return moccodes.DeleteFailed.String()
	} else if IsDeletePending(err) {
		return moccodes.DeletePending.String()
	} else if IsRunCommandFailed(err) {
		return moccodes.RunCommandFailed.String()
	} else if IsAccessDenied(err) {
		return moccodes.AccessDenied.String()
	} else if IsNoAuthenticationInformation(err) {
		return moccodes.NoAuthenticationInformation.String()
	} else if IsQuotaViolation(err) {
		return moccodes.QuotaViolation.String()
	} else if IsMeasurementUnitError(err) {
		return moccodes.MeasurementUnitError.String()
	} else if IsIPOutOfRange(err) {
		return moccodes.IPOutOfRange.String()
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

// GetGRPCError is used when returning errors from MOC GRPC services.
// It adds the MocCode to the error status details.
func GetGRPCError(err error) error {
	if err == nil {
		return err
	}

	var st *status.Status
	switch {
	case IsNotFound(err):
		st = status.New(codes.NotFound, err.Error())
	case IsAlreadyExists(err):
		st = status.New(codes.AlreadyExists, err.Error())
	default:
		// If we didn't match against any GRPC codes, then add the MocCode
		// to the error status details.
		st = status.New(codes.Unknown, err.Error())
	}

	st, _ = st.WithDetails(ErrorToProto(err))
	return st.Err()
}

// ParseGRPCError is when parsing errors from MOC GRPC services.
// Will extract the error as a MocError if GRPC code is Unknown.
func ParseGRPCError(err error) error {
	if err == nil {
		return nil
	}

	if !IsGRPCUnknown(err) {
		return err
	}

	st := status.Convert(err)
	for _, d := range st.Details() {
		switch detail := d.(type) {
		case *common.Error:
			return ProtoToMocError(detail)
		default:
			continue
		}
	}

	return err
}

// IsMocErrorCode wraps a call to GetMocErrorCode. It returns true only
// if the error has the same MocCode as the given code (no string matching).
func IsMocErrorCode(err error, code moccodes.MocCode) bool {
	return GetMocErrorCode(err) == code
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

func IsProviderNotReady(err error) bool {
	return checkError(err, ProviderNotReady)
}

func IsInconsistentVersion(err error) bool {
	return checkError(err, InconsistentVersion)
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
	if GetMocErrorCode(wrappedError) == GetMocErrorCode(err) {
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
