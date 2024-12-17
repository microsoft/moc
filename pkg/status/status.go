// Copyright (c) Microsoft Corporation
// Licensed under the Apache v2.0 license.
package status

import (
	"fmt"
	"strconv"
	"time"

	proto "github.com/golang/protobuf/proto"
	"github.com/microsoft/moc/pkg/errors"
	common "github.com/microsoft/moc/rpc/common"
)

// InitStatus
func InitStatus() *common.Status {
	return &common.Status{
		Health:             &common.Health{},
		ProvisioningStatus: &common.ProvisionStatus{},
		LastError:          &common.Error{},
		Version:            GenerateVersion(),
		DownloadStatus:     &common.DownloadStatus{},
		ValidationStatus:   &common.ValidationStatus{},
		PlacementStatus:    &common.PlacementStatus{},
		UploadStatus:       &common.UploadStatus{},
	}
}

// SetError
func SetError(s *common.Status, err error) {
	s.LastError = errors.ErrorToProto(err)
}

// SetHealth
func SetHealth(s *common.Status, hState common.HealthState, err ...error) {
	s.Health.PreviousState = s.Health.CurrentState
	s.Health.CurrentState = hState
	if len(err) > 0 {
		SetError(s, err[0])
	}
}

func IsHealthStateMissing(s *common.Status) bool {
	if s == nil {
		return false
	}

	if s.GetHealth() == nil {
		return false
	}

	hstatus := s.GetHealth().GetCurrentState()
	return (hstatus == common.HealthState_MISSING)
}

func IsHealthStateCritical(s *common.Status) bool {
	if s == nil {
		return false
	}

	if s.GetHealth() == nil {
		return false
	}

	hstatus := s.GetHealth().GetCurrentState()
	return (hstatus == common.HealthState_CRITICAL)
}

func IsDeleted(s *common.Status) bool {
	return (IsProvisionStatus(s, common.ProvisionState_DELETED) ||
		IsProvisionStatus(s, common.ProvisionState_DEPROVISIONED))
}

func IsProvisionStatus(s *common.Status, pState common.ProvisionState) bool {
	return s.ProvisioningStatus.CurrentState == pState
}

// SetProvisionStatus
func SetProvisionStatus(s *common.Status, pState common.ProvisionState, err ...error) {
	s.ProvisioningStatus.PreviousState = s.ProvisioningStatus.CurrentState
	s.ProvisioningStatus.CurrentState = pState
	if len(err) > 0 {
		SetError(s, err[0])
	}
}

// GenerateVersion
func GenerateVersion() *common.Version {
	return &common.Version{
		Number: strconv.FormatInt(time.Now().UnixNano(), 10),
	}
}

// GetProvisioningState string
func GetProvisioningState(status *common.ProvisionStatus) *string {
	stateString := status.GetCurrentState().String()
	return &stateString
}

// SetDownloadStatus
func SetDownloadStatus(s *common.Status, dProgressPercentage, dDownloadSizeInBytes, dFileSizeInBytes int64, err ...error) {
	s.DownloadStatus.ProgressPercentage = dProgressPercentage
	s.DownloadStatus.DownloadSizeInBytes = dDownloadSizeInBytes
	s.DownloadStatus.FileSizeInBytes = dFileSizeInBytes
	if len(err) > 0 {
		SetError(s, err[0])
	}
}

func SetValidationStatus(s *common.Status, validationState []*common.ValidationState) {
	s.ValidationStatus = new(common.ValidationStatus)
	s.ValidationStatus.ValidationState = validationState
}

func GetValidationStatus(s *common.Status) []*common.ValidationState {
	validationStatus := s.GetValidationStatus()
	if validationStatus != nil {
		return validationStatus.GetValidationState()
	}
	return nil
}

func SetPlacementStatus(s *common.Status, placementState *common.PlacementStatus) {
	s.PlacementStatus = new(common.PlacementStatus)
	s.PlacementStatus.Status = placementState.GetStatus()
	s.PlacementStatus.Message = placementState.GetMessage()
}

func GetPlacementStatus(s *common.Status) common.PlacementStatusType {
	return s.GetPlacementStatus().GetStatus()
}

// Set UploadError
func SetUploadError(s *common.Status, err ...error) {
	s.UploadStatus.LastUploadError = errors.ErrorToProto(err[0])
}

// SetUploadStatus
func SetUploadStatus(s *common.Status, dProgressPercentage, dUploadSizeInBytes, dFileSizeInBytes int64, err ...error) {
	if s.UploadStatus == nil {
		s.UploadStatus = &common.UploadStatus{}
	}
	s.UploadStatus.ProgressPercentage = dProgressPercentage
	s.UploadStatus.UploadSizeInBytes = dUploadSizeInBytes
	s.UploadStatus.FileSizeInBytes = dFileSizeInBytes
	if len(err) > 0 {
		SetUploadError(s, err[0])
	} else {
		s.UploadStatus.LastUploadError = nil
	}
}

// GetStatuses - converts status to map
func GetStatuses(status *common.Status) map[string]*string {
	statuses := map[string]*string{}

	// Provision and Health State require custom parsing as they are enums.
	// Otherwise enum 0 (UNKNOWN / NOT_KNOWN) will be an empty string.
	pstate := parseProvisioning(status.GetProvisioningStatus())
	statuses["ProvisionState"] = &pstate
	hstate := parseHealth(status.GetHealth())
	statuses["HealthState"] = &hstate

	errorStatus := status.GetLastError()
	if errorStatus != nil {
		errorStatusStr := errorStatus.String()
		statuses["Error"] = &errorStatusStr
	}

	version := status.GetVersion()
	if version != nil {
		statuses["Version"] = &version.Number
	}

	downloadStatus := status.GetDownloadStatus()
	if downloadStatus != nil {
		downloadStatusStr := downloadStatus.String()
		statuses["DownloadStatus"] = &downloadStatusStr
	}

	placementStatus := status.GetPlacementStatus()
	if placementStatus != nil {
		placementStatusStr := placementStatus.String()
		statuses["PlacementStatus"] = &placementStatusStr
	}
	uploadStatus := status.GetUploadStatus()
	if uploadStatus != nil {
		uploadStatusStr := uploadStatus.String()
		statuses["UploadStatus"] = &uploadStatusStr
	}

	return statuses
}

// GetFromStatuses - parses the map to status
func GetFromStatuses(statuses map[string]*string) (status *common.Status) {
	status = &common.Status{}
	if val, ok := statuses["ProvisionState"]; ok {
		ps := new(common.ProvisionStatus)
		proto.UnmarshalText(*val, ps)
		status.ProvisioningStatus = ps
	}
	if val, ok := statuses["HealthState"]; ok {
		ps := new(common.Health)
		proto.UnmarshalText(*val, ps)
		status.Health = ps
	}
	if val, ok := statuses["Error"]; ok {
		ps := new(common.Error)
		proto.UnmarshalText(*val, ps)
		status.LastError = ps
	}
	if val, ok := statuses["DownloadStatus"]; ok {
		ps := new(common.DownloadStatus)
		proto.UnmarshalText(*val, ps)
		status.DownloadStatus = ps
	}
	if val, ok := statuses["PlacementStatus"]; ok {
		ps := new(common.PlacementStatus)
		proto.UnmarshalText(*val, ps)
		status.PlacementStatus = ps
	}
	if val, ok := statuses["UploadStatus"]; ok {
		ps := new(common.UploadStatus)
		proto.UnmarshalText(*val, ps)
		status.UploadStatus = ps
	}

	return
}

// HealthState requires custom parsing as it is a proto enum. Otherwise enum 0 (NOT_KNOWN) will be an empty string.
func parseHealth(hstate *common.Health) string {
	if hstate == nil {
		return fmt.Sprintf("currentState:%s", common.HealthState_NOTKNOWN)
	}

	prevHealth, ok := common.HealthState_name[int32(hstate.GetPreviousState())]
	if !ok {
		prevHealth = common.HealthState_NOTKNOWN.String()
	}
	currHealth, ok := common.HealthState_name[int32(hstate.GetCurrentState())]
	if !ok {
		currHealth = common.HealthState_NOTKNOWN.String()
	}

	return fmt.Sprintf("currentState:%s previousState:%s", currHealth, prevHealth)
}

// ProvisionState requires custom parsing as it is a proto enum. Otherwise enum 0 (UNKNOWN) will be an empty string.
func parseProvisioning(pstate *common.ProvisionStatus) string {
	if pstate == nil {
		return fmt.Sprintf("currentState:%s", common.ProvisionState_UNKNOWN)
	}

	prevProv, ok := common.ProvisionState_name[int32(pstate.GetPreviousState())]
	if !ok {
		prevProv = common.ProvisionState_UNKNOWN.String()
	}
	currProv, ok := common.ProvisionState_name[int32(pstate.GetCurrentState())]
	if !ok {
		currProv = common.ProvisionState_UNKNOWN.String()
	}

	return fmt.Sprintf("currentState:%s previousState:%s", currProv, prevProv)
}
