package status

import (
	"fmt"
	"testing"

	"github.com/microsoft/moc/pkg/errors"
	"github.com/microsoft/moc/pkg/errors/codes"
	"github.com/microsoft/moc/rpc/common"
	"github.com/stretchr/testify/assert"
)

func newEmptyStatus() *common.Status {
	return &common.Status{
		Health:             &common.Health{},
		ProvisioningStatus: &common.ProvisionStatus{},
		LastError:          &common.Error{},
		Version:            &common.Version{},
		DownloadStatus:     &common.DownloadStatus{},
		ValidationStatus:   &common.ValidationStatus{},
	}
}

func TestSetError(t *testing.T) {
	tests := []struct {
		name                    string
		inputError              error
		expectedLastErrorString string
		expectedMsg             string
		expectedCode            uint32
	}{
		{
			name:                    "Nil error should clear the error",
			inputError:              nil,
			expectedLastErrorString: "",
			expectedMsg:             "",
			expectedCode:            codes.OK.ToUint32(),
		},
		{
			name:                    "Non-MocError results in codes.Unknown",
			inputError:              errors.New("simple error"),
			expectedLastErrorString: "Message:\"simple error\" Code:34 ",
			expectedMsg:             "simple error",
			expectedCode:            codes.Unknown.ToUint32(),
		},
		{
			name:                    "MocError results in the correct code and message",
			inputError:              errors.NotFound,
			expectedLastErrorString: "Message:\"Not Found\" Code:1 ",
			expectedMsg:             errors.NotFound.Error(),
			expectedCode:            codes.NotFound.ToUint32(),
		},
		{
			name:                    "Wrapped MocError results in the correct code and merged message",
			inputError:              errors.Wrapf(errors.NotFound, "more info here"),
			expectedLastErrorString: "Message:\"more info here: Not Found\" Code:1 ",
			expectedMsg:             "more info here: " + errors.NotFound.Error(),
			expectedCode:            codes.NotFound.ToUint32(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &common.Status{
				LastError: &common.Error{},
			}

			SetError(status, tt.inputError)

			assert.Equal(t, tt.expectedLastErrorString, status.LastError.String())
			assert.Equal(t, tt.expectedMsg, status.LastError.Message)
			assert.Equal(t, tt.expectedCode, status.LastError.Code)
		})
	}
}

// simulateStackTraceError simulates an error with a stack trace
func simulateStackTraceError(err error, desc string) error {
	err = returnFakeError(err, desc)
	return err
}

func returnFakeError(err error, desc string) error {
	return errors.Wrapf(err, "%s", desc)
}

func TestSetErrorWithStackTraceExcludesStackTrace(t *testing.T) {
	status := &common.Status{
		LastError: &common.Error{},
	}

	// Simulate an error with a stack trace
	errorDesc := "helpful in-depth description"
	simulatedError := simulateStackTraceError(errors.InvalidInput, errorDesc)

	SetError(status, simulatedError)

	assert.Equal(t, errorDesc+": "+errors.InvalidInput.Error(), status.LastError.Message)
	assert.Equal(t, codes.InvalidInput.ToUint32(), status.LastError.Code)

	// Check that the stack trace is not included in the LastError.Message
	stackTrace := fmt.Sprintf("%+v", simulatedError)

	// Make sure the stack trace is present by checking for function names
	assert.Contains(t, stackTrace, "returnFakeError")
	assert.Contains(t, stackTrace, "simulateStackTraceError")

	// Make sure the stack trace is not present in LastError msg by checking for function names
	assert.NotContains(t, status.LastError.Message, stackTrace)
	assert.NotContains(t, status.LastError.Message, "returnFakeError")
	assert.NotContains(t, status.LastError.Message, "simulateStackTraceError")
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

func TestHealthAndProvisionStateNilConversion(t *testing.T) {
	// Create a sample status with nil health state
	originalStatus := &common.Status{
		Health:             nil,
		ProvisioningStatus: nil,
		LastError:          &common.Error{},
		Version:            &common.Version{},
	}

	// Convert the status to a map using GetStatuses
	statusMap := GetStatuses(originalStatus)

	// Convert the map back to a status using GetFromStatuses
	convertedStatus := GetFromStatuses(statusMap)

	// Check that the health state in the converted status is NOT_KNOWN
	expectedHealthState := common.HealthState_NOTKNOWN
	if convertedStatus.Health == nil || convertedStatus.Health.CurrentState != expectedHealthState {
		t.Errorf("HealthState mismatch: got %v, want %v", convertedStatus.Health.GetCurrentState(), expectedHealthState)
	}

	// Check that the provision state in the converted status is UNKNOWN
	expectedProvisionState := common.ProvisionState_UNKNOWN
	if convertedStatus.ProvisioningStatus == nil || convertedStatus.ProvisioningStatus.CurrentState != expectedProvisionState {
		t.Errorf("ProvisionState mismatch: got %v, want %v", convertedStatus.ProvisioningStatus.GetCurrentState(), expectedProvisionState)
	}
}
