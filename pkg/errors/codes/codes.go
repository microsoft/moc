// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package codes

import (
	"strings"
)

// MocCode - error codes used by MOC
type MocCode uint32

const (
	OK MocCode = iota
	NotFound
	Degraded
	InvalidConfiguration
	InvalidInput
	InvalidType
	NotSupported
	AlreadyExists
	InUse
	Duplicates
	InvalidFilter
	Failed
	InvalidGroup
	InvalidVersion
	OldVersion
	OutOfCapacity
	OutOfNodeCapacity
	OutOfMemory
	UpdateFailed
	NotInitialized
	NotImplemented
	OutOfRange
	AlreadySet
	NotSet
	InconsistentState
	PendingState
	WrongHost
	PoolFull
	NoActionTaken
	Expired
	Revoked
	Timeout
	RunCommandFailed
	InvalidToken
	Unknown
	DeleteFailed
	DeletePending
	FileNotFound
	PathNotFound
	NotEnoughSpace
	AccessDenied
	BlobNotFound
	GenericFailure
	NoAuthenticationInformation
	MeasurementUnitError
	QuotaViolation
	IPOutOfRange
	MultipleErrors

	// This is not a valid code, it is used to get the maximum code value.
	// Any new codes should be defined above this.
	_maxCode
)

// errorMessages - map of error codes to their string representation. This is maintained solely for backwards compatibility.
// This, along with the func and map in codes_string.go, need to be updated whenever new codes are added.
var errorMessages = map[MocCode]string{
	OK:                          "", // No error so no message
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
	InvalidGroup:                "InvalidGroup",
	InvalidVersion:              "InvalidVersion",
	OldVersion:                  "OldVersion",
	OutOfCapacity:               "OutOfCapacity",
	OutOfNodeCapacity:           "OutOfNodeCapacity",
	OutOfMemory:                 "OutOfMemory",
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
	InvalidToken:                "InvalidToken",
	Unknown:                     "Unknown Reason",
	DeleteFailed:                "Delete Failed",
	DeletePending:               "Delete Pending",
	FileNotFound:                "The system cannot find the file specified",
	PathNotFound:                "The system cannot find the path specified",
	NotEnoughSpace:              "There is not enough space on the disk",
	AccessDenied:                "Access is denied",
	BlobNotFound:                "BlobNotFound",
	GenericFailure:              "Generic Failure",
	NoAuthenticationInformation: "NoAuthenticationInformation",
	MeasurementUnitError:        "Byte quantity must be a positive integer with a unit of measurement like",
	QuotaViolation:              "Quota Violation",
	IPOutOfRange:                "IP is out of range",
	MultipleErrors:              "Multiple Errors",
}

// IsValid - check if the code is a valid MocCode.
func (c MocCode) IsValid() bool {
	if c >= _maxCode {
		return false
	}

	_, inMap := errorMessages[c]
	if !inMap {
		return false
	}

	s := c.String()
	if strings.Contains(s, "MocCode(") {
		return false
	}

	return true
}

// String returns Unknown if the code is not a valid MocCode, otherwise it returns the string representation of the code.
func (c MocCode) ErrorMessage() string {
	if msg, exists := errorMessages[c]; exists {
		return msg
	}

	return errorMessages[Unknown]
}

func (c MocCode) ToUint32() uint32 {
	return uint32(c)
}

// Convert an uint32 to a MocCode. If the uint32 is not a valid MocCode, return Unknown.
func Convert(code uint32) MocCode {
	c := MocCode(code)
	if !c.IsValid() {
		return Unknown
	}
	return c
}
