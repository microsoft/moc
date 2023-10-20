// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.

package validations

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/microsoft/moc/pkg/errors"
)

func ValidateProxyURL(proxyURL string) error {
	parsedURL, err := url.ParseRequestURI(proxyURL)

	if err != nil {
		return errors.Wrapf(errors.InvalidInput, err.Error())
	}

	if parsedURL.Scheme != "http" {
		return errors.Wrapf(errors.InvalidInput, "Invalid proxy URL. The URL scheme should be http")
	}

	// Create a transport
	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedURL),
	}

	// Create a client
	client := &http.Client{
		Transport: transport,
	}

	// Test the HTTP GET request
	response, err := client.Get("http://bing.com")
	if err != nil {
		return errors.Wrapf(errors.InvalidInput, err.Error())
	} else {
		defer response.Body.Close()
		fmt.Println("Connected successfully to the proxy server")
	}

	return nil
}
