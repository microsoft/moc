// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package validations

import (
	"testing"
)

func Test_ValidateProxyURL(t *testing.T) {
	err := ValidateProxyURL("", "")
	expectedResult := "parse \"\": empty url: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected result was %s", expectedResult)
	}

	err = ValidateProxyURL("//akse2e:akse2e@skyproxy.ceccloud1.selfhost.corp.microsoft.com:3128", "")
	expectedResult = "Invalid proxy URL. The URL scheme should be http or https: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected result was %s", expectedResult)
	}

	err = ValidateProxyURL("http://akse2e:akse2e@.ceccloud1.selfhost.corp.microsoft.com:3128", "")
	expectedResult = "Get \"https://mcr.microsoft.com\": proxyconnect tcp: dial tcp: lookup .ceccloud1.selfhost.corp.microsoft.com: no such host: Invalid Input"
	if err.Error() != expectedResult {
		t.Fatalf("Test_ValidateProxyURL test case failed. Expected result was %s", expectedResult)
	}
}

func Test_ValidateCertFormatIsBase64(t *testing.T) {
	certContent := "-----BEGIN CERTIFICATE-----MIIDETCCAfkCFA6m/zJsUNjKnRp++MYKP+WSKpSQMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMxMDEzMTgwNjI1WhcNMjQxMDEyMTgwNjI1WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4HznjiYD16BW7gRvP/rHDpZ5vSVsn1cTrlNtdu3lr3HB3ibNVuF5hLRuA+/5687AmhhSB+ri6+of3R/BR2dSLmbC63qzqC/5JYkZEX7fb6RaiD5twds5EsSHukldLTE+H5lIF7JQhhRG0yz1Tl1BKC7uNSP7CmZOtC8Mf7wCYwwecADtvGE/bJsBLtxb4+QuMOQNV/Ldcb9Oy8ZifIplmNDlW0Jr4QMxffrXj4j1AVMEczNADkFTySEgWtILtvRnQvht6nxE7YBqubRs0zpGfFZFk9DBlwafZIMXXtv1/LNS8k54Fj3+KlXkiWy9jCNaWytJJUGubE3JJzPM1ya/TQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBi6TEo61Pvf80SCglSKIWszXhFpDzOPP4sy9eVmk6fg4cgt6Lv8ZNPns7U/7zqQLSmxlnhg2MkgGPRG/E9g8437AXd6GaQL+KQfwn+lJy9/xo5ERHZftsAIH4eDkVH42YAzZG8D5M2thdnwiu7JeGoEfrgCXCv7k8ewSTnFk7rH4y/IplVnBjitG93FDzGfnPAo5Oy/F8hX4ht6S3YTW3mvyPJ0z6M5oFZpjVHgG1BLXMG46BEKfVrE1YQ/KkRACPLH1MWDhuLKmjY4ohMLOOuy9c1OT0mhr6FREEBV9zs6bhfLt6UjIMiIqIz+FKPSjZr3EiSAiA8MD4/262q4KGM-----END CERTIFICATE-----"
	err := ValidateCertFormatIsBase64(certContent)
	if err != nil {
		t.Fatalf("Test_ValidateCertFormat test case failed - Certificate content is not base64 encoded")
	}
}
