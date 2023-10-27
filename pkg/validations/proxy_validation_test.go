// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package validations

import (
	"io/ioutil"
	"testing"
)

func Test_ValidateProxyURL(t *testing.T) {
	caCert, err := ioutil.ReadFile("../proxycert/proxy.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}
	caCertString := string(caCert)

	// Empty proxy url
	err = ValidateProxyURL("", "")
	expectedResult := "parse \"\": empty url: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}

	// Invalid proxy url
	err = ValidateProxyURL("//akse2e:akse2e@skyproxy.ceccloud1.selfhost.corp.microsoft.com:3128", caCertString)
	expectedResult = "Invalid proxy URL. The URL scheme should be http or https: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}

	// Invalid hostname
	err = ValidateProxyURL("http://akse2e:akse2e@.ceccloud1.selfhost.corp.microsoft.com:3128", caCertString)
	expectedResult = "Get \"https://mcr.microsoft.com\": proxyconnect tcp: dial tcp: lookup .ceccloud1.selfhost.corp.microsoft.com: no such host: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}
}

func Test_ValidateProxyCertificate(t *testing.T) {
	caCert, err := ioutil.ReadFile("../proxycert/proxy.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}
	caCertString := string(caCert)

	// Valid case
	err = ValidateProxyCertificate(caCertString)
	if err != nil {
		t.Fatalf("Test_ValidateProxyCertificate test case failed. %s", err.Error())
	}

	// Invalid certificate
	caCert, err = ioutil.ReadFile("../proxycert/sample-invalidCertificate.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}
	caCertString = string(caCert)
	err = ValidateProxyCertificate(caCertString)
	expectedResult := "Proxy server certificate is not base64 encoded. Please provide a base64 encoded certificate.: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyCertificate test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}

	// Expired certificate
	caCert, err = ioutil.ReadFile("../proxycert/sample-expiredCertificate.crt")
	if err != nil {
		t.Fatalf(err.Error())
	}
	caCertString = string(caCert)
	err = ValidateProxyCertificate(caCertString)
	expectedResult = "Proxy server SSL/TLS certificate has expired: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyCertificate test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}

	// Malformed certificate
	expectedResult = "x509: malformed certificate: Invalid Input"
	err = ValidateProxyCertificate("")
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyCertificate test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}
}
