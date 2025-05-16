// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package codes

import "strings"

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
	VolumeNotFound
	VolumeDegraded
	VolumeAccessInconsistent
	PreCheckFailed
	ProviderNotReady
	InconsistentVersion
	// This is not a valid code, it is used to get the maximum code value.
	// Any new codes should be defined above this.
	_maxCode
)

// IsValid - check if the code is a valid MocCode.
func (c MocCode) IsValid() bool {
	if c >= _maxCode {
		return false
	}

	// Check if the string has been defined for the code.
	if strings.Contains(c.String(), "MocCode") {
		return false
	}

	return true
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
