// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package auth

import (
	"net"
	"os"

	"github.com/microsoft/moc/pkg/certs"
	"github.com/microsoft/moc/pkg/marshal"
	wssdnet "github.com/microsoft/moc/pkg/net"
)

func readAccessFile(accessFileLocation string) (WssdConfig, error) {
	accessFile := WssdConfig{}
	err := marshal.FromJSONFile(accessFileLocation, &accessFile)
	if err != nil {
		return WssdConfig{}, err
	}

	return accessFile, nil
}

// GenerateClientKey generates key and self-signed cert if the file does not exist in WssdConfigLocation
// If the file exists the values from the fie is returned
func GenerateClientKey(loginconfig LoginConfig) (string, WssdConfig, error) {
	certBytes, err := marshal.FromBase64(loginconfig.Certificate)
	if err != nil {
		return "", WssdConfig{}, err
	}
	accessFile, err := readAccessFile(GetWssdConfigLocation())
	if err != nil {
		x509CertClient, keyClient, err := certs.GenerateClientCertificate(loginconfig.Name)
		if err != nil {
			return "", WssdConfig{}, err
		}

		certBytesClient := certs.EncodeCertPEM(x509CertClient)
		keyBytesClient := certs.EncodePrivateKeyPEM(keyClient)

		accessFile = WssdConfig{
			CloudCertificate:  "",
			ClientCertificate: marshal.ToBase64(string(certBytesClient)),
			ClientKey:         marshal.ToBase64(string(keyBytesClient)),
		}
	}

	if accessFile.CloudCertificate != "" {
		serverPem, err := marshal.FromBase64(accessFile.CloudCertificate)
		if err != nil {
			return "", WssdConfig{}, err
		}

		if string(certBytes) != string(serverPem) {
			certBytes = append(certBytes, serverPem...)
		}
	}

	accessFile.CloudCertificate = marshal.ToBase64(string(certBytes))
	return accessFile.ClientCertificate, accessFile, nil
}

func GenerateClientCsr(loginconfig LoginConfig) (string, WssdConfig, error) {
	certBytes, err := marshal.FromBase64(loginconfig.Certificate)
	if err != nil {
		return "", WssdConfig{}, err
	}
	accessFile, err := readAccessFile(GetWssdConfigLocation()) //nolint:golint,ineffassign
	cloudAgentIpAddress, err := wssdnet.GetIPAddress()
	if err != nil {
		return "", WssdConfig{}, err
	}

	localHostName, err := os.Hostname()
	if err != nil {
		return "", WssdConfig{}, err
	}

	cloudAgentIPAddress := wssdnet.StringToNetIPAddress(cloudAgentIpAddress)
	ipAddresses := []net.IP{wssdnet.StringToNetIPAddress(wssdnet.LOOPBACK_ADDRESS), cloudAgentIPAddress}
	dnsNames := []string{"localhost", localHostName}

	conf := &certs.Config{
		CommonName: loginconfig.Name,
		AltNames: certs.AltNames{
			DNSNames: dnsNames,
			IPs:      ipAddresses,
		},
	}
	x509Csr, keyClient, err := certs.GenerateCertificateRequest(conf, nil)
	if err != nil {
		return "", WssdConfig{}, err
	}

	accessFile = WssdConfig{
		CloudCertificate:  "",
		ClientCertificate: "",
		ClientKey:         marshal.ToBase64(string(keyClient)),
	}

	if accessFile.CloudCertificate != "" {
		serverPem, err := marshal.FromBase64(accessFile.CloudCertificate)
		if err != nil {
			return "", WssdConfig{}, err
		}

		if string(certBytes) != string(serverPem) {
			certBytes = append(certBytes, serverPem...)
		}
	}

	accessFile.CloudCertificate = marshal.ToBase64(string(certBytes))
	return string(x509Csr), accessFile, nil
}

// GenerateClientKeyWithName generates key and self-signed cert if the file does not exist in GetWssdConfigLocationName
// If the file exists the values from the fie is returned
func GenerateClientKeyWithName(loginconfig LoginConfig, subfolder, filename string) (string, WssdConfig, error) {
	certBytes, err := marshal.FromBase64(loginconfig.Certificate)
	if err != nil {
		return "", WssdConfig{}, err
	}
	accessFile, err := readAccessFile(GetMocConfigLocationName(subfolder, filename))
	if err != nil {
		x509CertClient, keyClient, err := certs.GenerateClientCertificate(loginconfig.Name)
		if err != nil {
			return "", WssdConfig{}, err
		}

		certBytesClient := certs.EncodeCertPEM(x509CertClient)
		keyBytesClient := certs.EncodePrivateKeyPEM(keyClient)

		accessFile = WssdConfig{
			CloudCertificate:  "",
			ClientCertificate: marshal.ToBase64(string(certBytesClient)),
			ClientKey:         marshal.ToBase64(string(keyBytesClient)),
		}
	}

	if accessFile.CloudCertificate != "" {
		serverPem, err := marshal.FromBase64(accessFile.CloudCertificate)
		if err != nil {
			return "", WssdConfig{}, err
		}

		if string(certBytes) != string(serverPem) {
			certBytes = append(certBytes, serverPem...)
		}
	}

	accessFile.CloudCertificate = marshal.ToBase64(string(certBytes))
	return accessFile.ClientCertificate, accessFile, nil
}
