// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.

package validations

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/microsoft/moc/pkg/errors"
	commonproto "github.com/microsoft/moc/rpc/common"
)

func ValidateProxyURL(proxyURL string) (*url.URL, error) {
	parsedURL, err := url.ParseRequestURI(proxyURL)

	if err != nil {
		return nil, errors.Wrapf(errors.InvalidInput, "%s", err.Error())
	}

	// Check if url scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, errors.Wrapf(errors.InvalidInput, "Invalid proxy URL. The URL scheme should be http or https")
	}

	return parsedURL, nil
}

func TestProxyUrlConnection(parsedURL *url.URL, certContent string, getRequestUrl string) error {
	// Create a certificate pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(certContent))

	// Create a transport
	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedURL),
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}

	// Create a client
	client := &http.Client{
		Transport: transport,
	}

	if getRequestUrl == "" {
		getRequestUrl = "https://mcr.microsoft.com"
	}

	// Test the HTTP GET request
	response, err := client.Get(getRequestUrl)
	if err != nil {
		return errors.Wrapf(errors.InvalidInput, "%s", err.Error())
	} else {
		defer response.Body.Close()
		fmt.Println("Connected successfully to the proxy server")
	}

	return nil
}

func ValidateProxyParameters(proxyConfig *commonproto.ProxyConfiguration) error {
	if proxyConfig == nil {
		return nil
	}
	// Validations for proxy parameters
	if len(proxyConfig.HttpProxy) > 0 {
		_, err := ValidateProxyURL(proxyConfig.HttpProxy)
		if err != nil {
			return err
		}
	}

	if len(proxyConfig.HttpsProxy) > 0 {
		_, err := ValidateProxyURL(proxyConfig.HttpsProxy)
		if err != nil {
			return err
		}
	}

	return nil
}
