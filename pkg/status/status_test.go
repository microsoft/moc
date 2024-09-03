package status

import (
	"testing"

	"github.com/microsoft/moc/rpc/common"
)

func newEmptyStatus() *common.Status {
	return &common.Status{
		Health:             &common.Health{},
		ProvisioningStatus: &common.ProvisionStatus{},
		LastError:          &common.Error{},
		Version:            &common.Version{},
	}
}

func TestHealthStatusConversion(t *testing.T) {
	// Create a sample status
	originalStatus := newEmptyStatus()
	originalStatus.Health = &common.Health{
		PreviousState: common.HealthState_NOTKNOWN, // Make sure NULL value is tested
		CurrentState:  common.HealthState_OK,
	}

	// Convert the status to a map using GetStatuses
	statusMap := GetStatuses(originalStatus)

	// Convert the map back to a status using GetFromStatuses
	convertedStatus := GetFromStatuses(statusMap)

	// Compare the original and converted Health states
	if originalStatus.Health.PreviousState != convertedStatus.Health.PreviousState {
		t.Errorf("PreviousState mismatch: got %v, want %v", convertedStatus.Health.PreviousState, originalStatus.Health.PreviousState)
	}

	if originalStatus.Health.CurrentState != convertedStatus.Health.CurrentState {
		t.Errorf("CurrentState mismatch: got %v, want %v", convertedStatus.Health.CurrentState, originalStatus.Health.CurrentState)
	}
}

func TestProvisionStatusConversion(t *testing.T) {
	// Create a sample status
	originalStatus := newEmptyStatus()
	originalStatus.ProvisioningStatus = &common.ProvisionStatus{
		PreviousState: common.ProvisionState_UNKNOWN, // Make sure NULL value is tested
		CurrentState:  common.ProvisionState_PROVISIONED,
	}

	// Convert the status to a map using GetStatuses
	statusMap := GetStatuses(originalStatus)

	// Convert the map back to a status using GetFromStatuses
	convertedStatus := GetFromStatuses(statusMap)

	// Compare the original and converted Provision states
	if originalStatus.ProvisioningStatus.PreviousState != convertedStatus.ProvisioningStatus.PreviousState {
		t.Errorf("PreviousState mismatch: got %v, want %v", convertedStatus.ProvisioningStatus.PreviousState, originalStatus.ProvisioningStatus.PreviousState)
	}

	if originalStatus.ProvisioningStatus.CurrentState != convertedStatus.ProvisioningStatus.CurrentState {
		t.Errorf("CurrentState mismatch: got %v, want %v", convertedStatus.ProvisioningStatus.CurrentState, originalStatus.ProvisioningStatus.CurrentState)
	}
}
