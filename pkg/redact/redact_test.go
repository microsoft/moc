// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package redact

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/microsoft/moc/rpc/cloudagent/security"
	"github.com/microsoft/moc/rpc/common"
	"github.com/stretchr/testify/assert"
)

func Test_RedactedMessage(t *testing.T) {
	id := security.Identity{
		Name:          "testIdentity",
		Id:            "123",
		ResourceGroup: "testGroup",
		Password:      "testPassword",
		Token:         "testToken",
		LocationName:  "testLocation",
		Certificates: map[string]string{
			"testKey1": "testVal1",
			"testKey2": "testVal2",
		},
		TokenExpiry: 30,
		ClientType:  common.ClientType_ADMIN,
		Tags: &common.Tags{
			Tags: []*common.Tag{
				{
					Key:   "testKey1",
					Value: "testValue1",
				},
				{
					Key:   "testKey2",
					Value: "testValue2",
				},
			},
		},
	}
	a := security.AuthenticationRequest{
		Identity: &id,
	}

	expectedAuthenticationRequest := security.AuthenticationRequest{
		Identity: &security.Identity{
			Name:          "testIdentity",
			Id:            "123",
			ResourceGroup: "testGroup",
			Password:      "** Redacted **",
			Token:         "** Redacted **",
			LocationName:  "testLocation",
			TokenExpiry:   30,
			ClientType:    common.ClientType_ADMIN,
			Tags: &common.Tags{
				Tags: []*common.Tag{
					{
						Key:   "testKey1",
						Value: "testValue1",
					},
					{
						Key:   "testKey2",
						Value: "testValue2",
					},
				},
			},
		},
	}
	expect := &expectedAuthenticationRequest

	msg := RedactedMessage(&a)

	redacted := (msg).(*security.AuthenticationRequest)
	if !proto.Equal(proto.Message(expect), redacted) {
		t.Errorf("Redacted AuthenticationRequest: {%v} does not match expected: {%v}", redacted, expectedAuthenticationRequest)
	}
}

func TestRedactedError(t *testing.T) {
	// Mock security.Identity
	id := security.Identity{
		Name:          "testIdentity",
		Id:            "123",
		ResourceGroup: "testGroup",
		Password:      "testPassword",
		Token:         "testToken",
		LocationName:  "testLocation",
		Certificates: map[string]string{
			"testKey1": "testVal1",
			"testKey2": "testVal2",
		},
		TokenExpiry: 30,
		ClientType:  common.ClientType_ADMIN,
		Tags: &common.Tags{
			Tags: []*common.Tag{
				{
					Key:   "testKey1",
					Value: "testValue1",
				},
				{
					Key:   "testKey2",
					Value: "testValue2",
				},
			},
		},
	}

	a := security.AuthenticationRequest{
		Identity: &id,
	}

	// Call the RedactedError function
	err := fmt.Errorf("authentication failed for user %s with password %s", id.Name, id.Password)
	RedactError(&a, &err)

	assert.Equal(t, err.Error(), "authentication failed for user testIdentity with password ** Redacted **")
}
func TestRedactErrorJsonSensitiveField(t *testing.T) {
	tests := []struct {
		name          string
		inputJson     string
		inputError    string
		expectedError string
	}{
		{
			name:          "Redact private-key in JSON",
			inputJson:     `{"private-key": "sensitiveKey", "other-key": "othervalue"}`,
			inputError:    "error with sensitiveKey",
			expectedError: "error with ** Redacted **",
		},
		{
			name:          "No private-key in JSON",
			inputJson:     `{"other-key": "otherValue"}`,
			inputError:    "error with no sensitive data",
			expectedError: "error with no sensitive data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := reflect.ValueOf(tt.inputJson)
			err := fmt.Errorf(tt.inputError)

			redactErrorJsonSensitiveField(val, &err)

			assert.Equal(t, fmt.Errorf(tt.expectedError), err)
		})
	}
}
