// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package redact

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/microsoft/moc/rpc/cloudagent/security"
	"github.com/microsoft/moc/rpc/common"
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
