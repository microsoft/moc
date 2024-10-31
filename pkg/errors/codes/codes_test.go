package codes

import (
	"testing"
)

func TestErrorMessages(t *testing.T) {
	// Test that all error codes have a corresponding message
	maxMocCode := int(_maxCode) - 1
	for i := 0; i <= maxMocCode; i++ {
		mocCode := MocCode(i)
		if !mocCode.IsValid() {
			t.Errorf("MocCode %d is not valid, ensure that it has been assigned a string and error code", mocCode)
		}
	}
}
