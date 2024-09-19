// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package codes

// MocCode - error codes used by MOC
type MocCode uint32

const (
	OK                          MocCode = 0
	NotFound                    MocCode = 1
	Degraded                    MocCode = 2
	InvalidConfiguration        MocCode = 3
	InvalidInput                MocCode = 4
	InvalidType                 MocCode = 5
	NotSupported                MocCode = 6
	AlreadyExists               MocCode = 7
	InUse                       MocCode = 8
	Duplicates                  MocCode = 9
	InvalidFilter               MocCode = 10
	Failed                      MocCode = 11
	InvalidGroup                MocCode = 12
	InvalidVersion              MocCode = 13
	OldVersion                  MocCode = 14
	OutOfCapacity               MocCode = 15
	OutOfNodeCapacity           MocCode = 16
	OutOfMemory                 MocCode = 17
	UpdateFailed                MocCode = 18
	NotInitialized              MocCode = 19
	NotImplemented              MocCode = 20
	OutOfRange                  MocCode = 21
	AlreadySet                  MocCode = 22
	NotSet                      MocCode = 23
	InconsistentState           MocCode = 24
	PendingState                MocCode = 25
	WrongHost                   MocCode = 26
	PoolFull                    MocCode = 27
	NoActionTaken               MocCode = 28
	Expired                     MocCode = 29
	Revoked                     MocCode = 30
	Timeout                     MocCode = 31
	RunCommandFailed            MocCode = 32
	InvalidToken                MocCode = 33
	Unknown                     MocCode = 34
	DeleteFailed                MocCode = 35
	DeletePending               MocCode = 36
	FileNotFound                MocCode = 37
	PathNotFound                MocCode = 38
	NotEnoughSpace              MocCode = 39
	AccessDenied                MocCode = 40
	BlobNotFound                MocCode = 41
	GenericFailure              MocCode = 42
	NoAuthenticationInformation MocCode = 43
	MeasurementUnitError        MocCode = 44
	QuotaViolation              MocCode = 45
	IPOutOfRange                MocCode = 46
	MultipleErrors              MocCode = 47
)

// errorMessages - map of error codes to their string representation. This needs to be updated whenever new codes are added.
var errorMessages = map[MocCode]string{
	OK:                          "",
	NotFound:                    "Not Found",
	Degraded:                    "Degraded",
	InvalidConfiguration:        "Invalid Configuration",
	InvalidInput:                "Invalid Input",
	InvalidType:                 "Invalid Type",
	NotSupported:                "Not Supported",
	AlreadyExists:               "Already Exists",
	InUse:                       "In Use",
	Duplicates:                  "Duplicates",
	InvalidFilter:               "Invalid Filter",
	Failed:                      "Failed",
	InvalidGroup:                "Invalid Group",
	InvalidVersion:              "Invalid Version",
	OldVersion:                  "Old Version",
	OutOfCapacity:               "Out Of Capacity",
	OutOfNodeCapacity:           "Out Of Node Capacity",
	OutOfMemory:                 "Out Of Memory",
	UpdateFailed:                "Update Failed",
	NotInitialized:              "Not Initialized",
	NotImplemented:              "Not Implemented",
	OutOfRange:                  "Out of Range",
	AlreadySet:                  "Already Set",
	NotSet:                      "Not Set",
	InconsistentState:           "Inconsistent State",
	PendingState:                "Pending State",
	WrongHost:                   "Wrong Host",
	PoolFull:                    "The pool is full",
	NoActionTaken:               "No Action Taken",
	Expired:                     "Expired",
	Revoked:                     "Revoked",
	Timeout:                     "Timed out",
	RunCommandFailed:            "Run Command Failed",
	InvalidToken:                "Invalid Token",
	Unknown:                     "Unknown Reason",
	DeleteFailed:                "Delete Failed",
	DeletePending:               "Delete Pending",
	FileNotFound:                "The system cannot find the file specified",
	PathNotFound:                "The system cannot find the path specified",
	NotEnoughSpace:              "There is not enough space on the disk",
	AccessDenied:                "Access is denied",
	BlobNotFound:                "Blob Not Found",
	GenericFailure:              "Generic Failure",
	NoAuthenticationInformation: "No Authentication Information",
	MeasurementUnitError:        "Byte quantity must be a positive integer with a unit of measurement like",
	QuotaViolation:              "Quota Violation",
	IPOutOfRange:                "IP is out of range",
	MultipleErrors:              "Multiple Errors",
}

// isValid - check if the MocCode is valid. This needs to be updated whenever new codes are added.
func (c MocCode) IsValid() bool {
	return c <= MultipleErrors
}

func (c MocCode) String() string {
	if msg, exists := errorMessages[c]; exists {
		return msg
	}

	return errorMessages[Unknown]
}

// Convert an int32 to a MocCode. If the int32 is not a valid MocCode, return Unknown.
func Convert(code int32) MocCode {
	c := MocCode(uint32(code))
	if !c.IsValid() {
		return Unknown
	}
	return c
}
