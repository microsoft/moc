// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package redact

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
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

func TestNegativeRedactedError(t *testing.T) {
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
	err1 := &err
	*err1 = nil

	RedactError(&a, err1)

	assert.Equal(t, *err1, nil)
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
		{
			name:          "Redact sasURI in JSON",
			inputJson:     `{"private-key": "sensitiveKey2", "sasURI": "https://usgovcloudapi.net/"}`,
			inputError:    "error with sensitiveKey2, sasURI: https://usgovcloudapi.net/",
			expectedError: "error with ** Redacted **, sasURI: ** Redacted **",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := reflect.ValueOf(tt.inputJson)
			err := fmt.Errorf("%s", tt.inputError)

			redactErrorJsonSensitiveField(val, &err)

			assert.Equal(t, fmt.Errorf("%s", tt.expectedError), err)
		})
	}
}

func TestRedactErrorURL(t *testing.T) {
	type args struct {
		err error
		uri string
	}
	tests := []struct {
		name      string
		args      args
		uri       string
		wantError bool
	}{
		{name: "valid URI", args: struct {
			err error
			uri string
		}{err: &url.Error{
			Op:  "Head",
			URL: "https://sas.azure.net/test?sp=sljsdf&st=2025-01-31T10:33:25Z&sv=2022-10-02&spr=3lskdjfoi23y9owh9u23fgn",
			Err: errors.New("unable to reach host"),
		},
			uri: "https://sas.azure.net/test?sp=sljsdf&st=2025-01-31T10:33:25Z&sv=2022-10-02&spr=3lskdjfoi23y9owh9u23fgn"}, wantError: false},

		{name: "uri with token", args: struct {
			err error
			uri string
		}{err: &url.Error{
			Op:  "Head",
			URL: "https://sas.azure.net/test?se=2025-01-31T18%3A33%3A25Z&sig=7k%3D&sp=r&spr=https&sr=b&st=2025-01-31T10%3A33%3A25Z&sv=2022-11-02",
			Err: errors.New("unable to reach host"),
		},
			uri: "https://sas.azure.net/test?se=2025-01-31T18%3A33%3A25Z&sig=7k%3D&sp=r&spr=https&sr=b&st=2025-01-31T10%3A33%3A25Z&sv=2022-11-02"}, wantError: false},
		{name: "empty uri", args: struct {
			err error
			uri string
		}{err: &url.Error{
			Op:  "Head",
			URL: "",
			Err: errors.New("unable to reach host"),
		},
			uri: ""}, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RedactErrorURL(tt.args.err)
			if tt.wantError != strings.Contains(tt.args.err.Error(), tt.args.uri) {
				t.Errorf("RedactErrorURL() got = %v, want %v", tt.args.err, tt.wantError)
			}
		})
	}
}
