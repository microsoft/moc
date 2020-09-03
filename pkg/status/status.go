// Copyright (c) Microsoft Corporation
// Licensed under the Apache v2.0 license.
package status

import (
	"fmt"
	"strconv"
	"time"

	"github.com/microsoft/moc-proto/pkg/marshal"
	common "github.com/microsoft/moc-proto/rpc/common"
)

// InitStatus
func InitStatus() *common.Status {
	return &common.Status{
		Health:             &common.Health{},
		ProvisioningStatus: &common.ProvisionStatus{},
		LastError:          &common.Error{},
		Version:            GenerateVersion(),
	}
}

// SetError
func SetError(s *common.Status, err error) {
	if err != nil {
		s.LastError.Message = fmt.Sprintf("%+v", err)
	} else {
		s.LastError.Message = "" // Clear the error
	}
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
	hstatus := s.GetHealth().GetCurrentState()
	return (hstatus == common.HealthState_MISSING)
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

// GetStatuses - converts status to map
func GetStatuses(status *common.Status) map[string]*string {
	statuses := map[string]*string{}
	pstate := status.GetProvisioningStatus().String()
	statuses["ProvisionState"] = &pstate
	hstate := status.GetHealth().String()
	statuses["HealthState"] = &hstate
	estate := status.GetLastError().String()
	statuses["Error"] = &estate
	version := status.GetVersion().Number
	statuses["Version"] = &version
	return statuses
}

// GetFromStatuses - parses the map to status
func GetFromStatuses(statuses map[string]*string) (status *common.Status) {
	status = &common.Status{}
	if val, ok := statuses["ProvisionState"]; ok {
		ps := common.ProvisionStatus{}
		_ = marshal.FromJSON(*val, &ps)
		status.ProvisioningStatus = &ps
	}
	if val, ok := statuses["HealthState"]; ok {
		ps := common.Health{}
		_ = marshal.FromJSON(*val, &ps)
		status.Health = &ps
	}
	if val, ok := statuses["Error"]; ok {
		ps := common.Error{}
		_ = marshal.FromJSON(*val, &ps)
		status.LastError = &ps
	}
	return
}
