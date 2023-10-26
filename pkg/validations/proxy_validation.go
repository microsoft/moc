// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.

package validations

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/microsoft/moc/pkg/errors"
)

func ValidateProxyURL(proxyURL string, certContent string) error {
	parsedURL, err := url.ParseRequestURI(proxyURL)

	if err != nil {
		return errors.Wrapf(errors.InvalidInput, err.Error())
	}

	// Check if url scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return errors.Wrapf(errors.InvalidInput, "Invalid proxy URL. The URL scheme should be http or https")
	}

	// Create a certificate pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(certContent))

	// Create a transport
	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedURL),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
	}

	// Create a client
	client := &http.Client{
		Transport: transport,
	}

	// Test the HTTP GET request
	response, err := client.Get("https://mcr.microsoft.com")
	if err != nil {
		return errors.Wrapf(errors.InvalidInput, err.Error())
	} else {
		defer response.Body.Close()
		fmt.Println("Connected successfully to the proxy server")
	}

	return nil
}

func ValidateProxyCertificate(certContent string) error {
	certContent = strings.Replace(certContent, "-----BEGIN CERTIFICATE-----", "", -1)
	certContent = strings.Replace(certContent, "-----END CERTIFICATE-----", "", -1)

	// Check if certificate is base64-encoded
	_, err := base64.StdEncoding.DecodeString(certContent)
	if err != nil {
		return errors.Wrapf(errors.InvalidInput, "Proxy server certificate is not base64 encoded. Please provide a base64 encoded certificate.")
	}

	// Decode the base64-encoded certificate
	certBytes, _ := base64.StdEncoding.DecodeString(certContent)
	if certBytes == nil {
		return errors.Wrapf(errors.InvalidInput, "Failed to decode certificate")
	}
	// Parse the decoded certificate
	caCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return errors.Wrapf(errors.InvalidInput, err.Error())
	}

	// Check for the expiry of certificate
	currentTime := time.Now()
	if currentTime.After(caCert.NotAfter) {
		return errors.Wrapf(errors.InvalidInput, "Proxy server SSL/TLS certificate has expired")
	}

	return nil
}
