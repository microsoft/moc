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
)

func ValidateProxyURL(proxyURL string) (*url.URL, error) {
	parsedURL, err := url.ParseRequestURI(proxyURL)

	if err != nil {
		return nil, errors.Wrapf(errors.InvalidInput, err.Error())
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
		return errors.Wrapf(errors.InvalidInput, err.Error())
	} else {
		defer response.Body.Close()
		fmt.Println("Connected successfully to the proxy server")
	}

	return nil
}
