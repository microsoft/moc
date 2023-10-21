// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package validations

import (
	"testing"
)

func Test_ValidateProxyURL(t *testing.T) {
	err := ValidateProxyURL("")
	expectedResult := "parse \"\": empty url: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected result was %s", expectedResult)
	}

	err = ValidateProxyURL("https://akse2e:akse2e@skyproxy.ceccloud1.selfhost.corp.microsoft.com:3128")
	expectedResult = "Invalid proxy URL. The URL scheme should be http: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected result was %s", expectedResult)
	}

	err = ValidateProxyURL("http://akse2e:akse2e@.ceccloud1.selfhost.corp.microsoft.com:3128")
	expectedResult = "Get \"http://bing.com\": proxyconnect tcp: dial tcp: lookup .ceccloud1.selfhost.corp.microsoft.com: no such host: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected result was %s", expectedResult)
	}
}

func Test_ValidateCertFormatIsBase64(t *testing.T) {
	certContent := "-----BEGIN CERTIFICATE-----MIIDETCCAfkCFAjEhG/xypxPKN1URzLmLISCPuTVMA0GCSqGSIb3DQEBCwUAMEUx-----END CERTIFICATE-----"
	err := ValidateCertFormatIsBase64(certContent)
	if err != nil {
		t.Fatalf("Test_ValidateCertFormat test case failed - Certificate content is not base64 encoded")
	}
}
