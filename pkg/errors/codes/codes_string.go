// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package codes

import (
	"strconv"
)

// String returns the string representation of the MocCode
func (c MocCode) String() string {
	switch c {
	case OK:
		return ""
	case NotFound:
		return "NotFound"
	case Degraded:
		return "Degraded"
	case InvalidConfiguration:
		return "InvalidConfiguration"
	case InvalidInput:
		return "InvalidInput"
	case InvalidType:
		return "InvalidType"
	case NotSupported:
		return "NotSupported"
	case AlreadyExists:
		return "AlreadyExists"
	case InUse:
		return "InUse"
	case Duplicates:
		return "Duplicates"
	case InvalidFilter:
		return "InvalidFilter"
	case Failed:
		return "Failed"
	case InvalidGroup:
		return "InvalidGroup"
	case InvalidVersion:
		return "InvalidVersion"
	case OldVersion:
		return "OldVersion"
	case OutOfCapacity:
		return "OutOfCapacity"
	case OutOfNodeCapacity:
		return "OutOfNodeCapacity"
	case OutOfMemory:
		return "OutOfMemory"
	case UpdateFailed:
		return "UpdateFailed"
	case NotInitialized:
		return "NotInitialized"
	case NotImplemented:
		return "NotImplemented"
	case OutOfRange:
		return "OutOfRange"
	case AlreadySet:
		return "AlreadySet"
	case NotSet:
		return "NotSet"
	case InconsistentState:
		return "InconsistentState"
	case PendingState:
		return "PendingState"
	case WrongHost:
		return "WrongHost"
	case PoolFull:
		return "PoolFull"
	case NoActionTaken:
		return "NoActionTaken"
	case Expired:
		return "Expired"
	case Revoked:
		return "Revoked"
	case Timeout:
		return "Timeout"
	case RunCommandFailed:
		return "RunCommandFailed"
	case InvalidToken:
		return "InvalidToken"
	case Unknown:
		return "Unknown"
	case DeleteFailed:
		return "DeleteFailed"
	case DeletePending:
		return "DeletePending"
	case FileNotFound:
		return "FileNotFound"
	case PathNotFound:
		return "PathNotFound"
	case NotEnoughSpace:
		return "NotEnoughSpace"
	case AccessDenied:
		return "AccessDenied"
	case BlobNotFound:
		return "BlobNotFound"
	case GenericFailure:
		return "GenericFailure"
	case NoAuthenticationInformation:
		return "NoAuthenticationInformation"
	case MeasurementUnitError:
		return "MeasurementUnitError"
	case QuotaViolation:
		return "QuotaViolation"
	case IPOutOfRange:
		return "IPOutOfRange"
	case VolumeNotFound:
		return "VolumeNotFound"
	case VolumeDegraded:
		return "VolumeDegraded"
	case VolumeAccessInconsistent:
		return "VolumeAccessInconsistent"
	case PreCheckFailed:
		return "PreCheckFailed"
	default:
		return "MocCode(" + strconv.FormatUint(uint64(c), 10) + ")"
	}
}
