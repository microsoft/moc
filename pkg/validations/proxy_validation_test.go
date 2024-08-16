// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package validations

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/microsoft/moc/pkg/certs"
	commonproto "github.com/microsoft/moc/rpc/common"
	"github.com/stretchr/testify/assert"
)

func Test_ValidateProxyURL(t *testing.T) {
	// Empty proxy url
	_, err := ValidateProxyURL("")
	expectedResult := "parse \"\": empty url: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}

	// Invalid proxy url
	_, err = ValidateProxyURL("w3proxy.netscape.com:3128")
	expectedResult = "Invalid proxy URL. The URL scheme should be http or https: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}
}

func Test_TestProxyUrlConnection(t *testing.T) {
	caCert, _, err := certs.GenerateClientCertificate("ValidCertificate")
	if err != nil {
		t.Fatalf(err.Error())
	}
	certBytes := certs.EncodeCertPEM(caCert)
	caCertString := string(certBytes)

	parsedUrl, _ := ValidateProxyURL("http://w3proxy.netscape.com:3128")
	// Invalid hostname
	err = TestProxyUrlConnection(parsedUrl, caCertString, "")
	expectedResult := "Get \"https://mcr.microsoft.com\": proxyconnect tcp: dial tcp: lookup w3proxy.netscape.com"
	assert.ErrorContains(t, err, expectedResult)

	// Valid case
	proxy := NewProxy()
	defer proxy.Target.Close()
	parsedUrl, _ = ValidateProxyURL(proxy.Target.URL)
	err = TestProxyUrlConnection(parsedUrl, "", "http://www.bing.com")
	if err != nil {
		t.Fatalf("Test_TestProxyUrlConnection test case failed. %s", err.Error())
	}
}

func Test_ValidateProxyParameters(t *testing.T) {
	config := commonproto.ProxyConfiguration{}
	proxy := NewProxy()
	defer proxy.Target.Close()
	config.HttpProxy = proxy.Target.URL
	config.HttpsProxy = proxy.Target.URL

	// valid case
	err := ValidateProxyParameters(&config)
	if err != nil {
		t.Fatalf("Test_ValidateProxyParameters test case failed. %s", err.Error())
	}

	// invalid case - invalid url
	config.HttpProxy = "w3proxy.netscape.com:3128"
	err = ValidateProxyParameters(&config)
	expectedResult := "Invalid proxy URL. The URL scheme should be http or https: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyParameters test case failed. Expected error %s but got %s", expectedResult, err.Error())
	}
}

// Proxy is a simple proxy server for unit tests.
type Proxy struct {
	Target *httptest.Server
}

// NewProxy creates a new proxy server for unit tests.
func NewProxy() *Proxy {
	target := httptest.NewServer(http.DefaultServeMux)
	return &Proxy{Target: target}
}
