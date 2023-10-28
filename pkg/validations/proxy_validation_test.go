// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package validations

import (
	"testing"

	"github.com/microsoft/moc/pkg/certs"
)

func Test_ValidateProxyURLAndTestConnection(t *testing.T) {
	caCert, _, err := certs.GenerateClientCertificate("ValidCertificate")
	if err != nil {
		t.Fatalf(err.Error())
	}
	certBytes := certs.EncodeCertPEM(caCert)
	caCertString := string(certBytes)

	// Empty proxy url
	err = ValidateProxyURLAndTestConnection("", "", "")
	expectedResult := "parse \"\": empty url: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}

	// Invalid proxy url
	err = ValidateProxyURLAndTestConnection("//akse2e:akse2e@skyproxy.ceccloud1.selfhost.corp.microsoft.com:3128", caCertString, "")
	expectedResult = "Invalid proxy URL. The URL scheme should be http or https: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}

	// Invalid hostname
	err = ValidateProxyURLAndTestConnection("http://akse2e:akse2e@.ceccloud1.selfhost.corp.microsoft.com:3128", caCertString, "")
	expectedResult = "Get \"https://mcr.microsoft.com\": proxyconnect tcp: dial tcp: lookup .ceccloud1.selfhost.corp.microsoft.com: no such host: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}
}
