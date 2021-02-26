// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package certs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"
)

func Test_CACerts(t *testing.T) {
	ca, key, err := GenerateClientCertificate("test CA")
	if err != nil {
		t.Errorf("Error creation in CA certificate failed: %s", err.Error())
	}

	rootSigner, err := tls.X509KeyPair(EncodeCertPEM(ca), EncodePrivateKeyPEM(key))
	if err != nil {
		t.Errorf("Failed to load root key pair: %v", err)
		return
	}

	caConfig := CAConfig{
		RootSigner: &rootSigner,
	}

	caAuth, err := NewCertificateAuthority(&caConfig)
	if err != nil {
		t.Errorf("Error creation CA Auth: %s", err.Error())
	}

	conf := Config{
		CommonName:   "Test Cert",
		Organization: []string{"microsoft"},
	}
	conf.AltNames.DNSNames = []string{"Test Cert"}
	csr, keyClientPem, err := GenerateCertificateRequest(&conf, nil)
	if err != nil {
		t.Errorf("Error creation in CSR: %s", err.Error())
	}

	keyClient, err := DecodePrivateKeyPEM(keyClientPem)
	if err != nil {
		t.Errorf("Failed Decoding privatekey: %s", err.Error())
	}
	clientCertPem, err := caAuth.SignRequest(csr, nil, nil)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	clientCert, err := DecodeCertPEM(clientCertPem)
	if err != nil {
		t.Errorf("Failed Decoding cert: %s", err.Error())
	}

	if (clientCert.NotAfter.Sub(clientCert.NotBefore)) != (time.Hour * 24 * 365) {
		t.Errorf("Invalid certificate expiry")
	}

	foundCertDER := false
	foundRenewCount := false
	for _, ext := range clientCert.Extensions {
		if ext.Id.Equal(oidOriginalCertificate) {
			foundCertDER = true
		} else if ext.Id.Equal(oidRenewCount) {
			foundRenewCount = true
		}
	}

	if foundRenewCount || foundCertDER {
		t.Errorf("Found certDER or renewCount Extensions")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: "Test Cert",
	}

	if _, err := clientCert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	if _, err = tls.X509KeyPair(EncodeCertPEM(clientCert), EncodePrivateKeyPEM(keyClient)); err != nil {
		t.Errorf("Error Verifying key and cert: %s", err.Error())
	}
}

func Test_CACertsVerify(t *testing.T) {
	ca, key, err := GenerateClientCertificate("test CA")
	if err != nil {
		t.Errorf("Error creation in CA certificate failed: %s", err.Error())
	}

	rootSigner, err := tls.X509KeyPair(EncodeCertPEM(ca), EncodePrivateKeyPEM(key))
	if err != nil {
		t.Errorf("Failed to load root key pair: %v", err)
		return
	}

	caConfig := CAConfig{
		RootSigner: &rootSigner,
	}

	caAuth, err := NewCertificateAuthority(&caConfig)
	if err != nil {
		t.Errorf("Error creation CA Auth: %s", err.Error())
	}

	conf := Config{
		CommonName:   "Test Cert",
		Organization: []string{"microsoft"},
	}
	conf.AltNames.DNSNames = []string{"Test Cert"}
	csr, keyClientPem, err := GenerateCertificateRequest(&conf, nil)
	if err != nil {
		t.Errorf("Error creation in CSR: %s", err.Error())
	}
	keyClient, err := DecodePrivateKeyPEM(keyClientPem)
	if err != nil {
		t.Errorf("Failed Decoding privatekey: %s", err.Error())
	}
	signConf := SignConfig{Offset: time.Second * 5}
	clientCertPem, err := caAuth.SignRequest(csr, nil, &signConf)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	clientCert, err := DecodeCertPEM(clientCertPem)
	if err != nil {
		t.Errorf("Failed Decoding cert: %s", err.Error())
	}

	if (clientCert.NotAfter.Sub(clientCert.NotBefore)) != signConf.Offset {
		t.Errorf("Invalid certificate expiry")
	}

	foundCertDER := false
	foundRenewCount := false
	for _, ext := range clientCert.Extensions {
		if ext.Id.Equal(oidOriginalCertificate) {
			foundCertDER = true
		} else if ext.Id.Equal(oidRenewCount) {
			foundRenewCount = true
		}
	}

	if foundRenewCount || foundCertDER {
		t.Errorf("Found certDER or renewCount Extensions")
	}

	clientCerts := [][]byte{clientCert.Raw}

	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

	time.Sleep(time.Second * 6)
	if err = caAuth.VerifyClientCertificate(clientCerts); err == nil {
		panic("failed to verify certificate after Expiry")
	}
	if _, err = tls.X509KeyPair(EncodeCertPEM(clientCert), EncodePrivateKeyPEM(keyClient)); err != nil {
		t.Errorf("Error Verifying key and cert: %s", err.Error())
	}
}

func Test_CACertsRenewVerify(t *testing.T) {
	ca, key, err := GenerateClientCertificate("test CA")
	if err != nil {
		t.Errorf("Error creation in CA certificate failed: %s", err.Error())
	}

	rootSigner, err := tls.X509KeyPair(EncodeCertPEM(ca), EncodePrivateKeyPEM(key))
	if err != nil {
		t.Errorf("Failed to load root key pair: %v", err)
		return
	}

	caConfig := CAConfig{
		RootSigner: &rootSigner,
	}

	caAuth, err := NewCertificateAuthority(&caConfig)
	if err != nil {
		t.Errorf("Error creation CA Auth: %s", err.Error())
	}

	conf := Config{
		CommonName:   "Test Cert",
		Organization: []string{"microsoft"},
	}
	conf.AltNames.DNSNames = []string{"Test Cert"}
	csr, keyClientPem, err := GenerateCertificateRequest(&conf, nil)
	if err != nil {
		t.Errorf("Error creation in CSR: %s", err.Error())
	}
	keyClient, err := DecodePrivateKeyPEM(keyClientPem)
	if err != nil {
		t.Errorf("Failed Decoding privatekey: %s", err.Error())
	}
	signConf := SignConfig{Offset: time.Second * 5}
	clientCertPem, err := caAuth.SignRequest(csr, nil, &signConf)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}
	clientCert, err := DecodeCertPEM(clientCertPem)
	if err != nil {
		t.Errorf("Failed Decoding cert: %s", err.Error())
	}
	// Test certificate duration
	if (clientCert.NotAfter.Sub(clientCert.NotBefore)) != signConf.Offset {
		t.Errorf("Invalid certificate expiry")
	}

	clientCerts := [][]byte{clientCert.Raw}

	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

	oldcert, err := tls.X509KeyPair(EncodeCertPEM(clientCert), EncodePrivateKeyPEM(keyClient))
	if err != nil {
		t.Errorf("Error creating X509 keypair: %s", err.Error())
	}

	// ================= Renew 1 ========================
	csr1, keyClient1Pem, err := GenerateCertificateRenewRequest(&oldcert)
	if err != nil {
		t.Errorf("Error creating renew CSR: %s", err.Error())
	}
	keyClient1, err := DecodePrivateKeyPEM(keyClient1Pem)
	if err != nil {
		t.Errorf("Failed Decoding privatekey: %s", err.Error())
	}
	signConf = SignConfig{Offset: time.Second * 20}
	certClient1Pem, err := caAuth.SignRequest(csr1, clientCert.Raw, &signConf)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	certClient1, err := DecodeCertPEM(certClient1Pem)
	if err != nil {
		t.Errorf("Failed Decoding cert: %s", err.Error())
	}

	// Test certificate duration
	if (certClient1.NotAfter.Sub(certClient1.NotBefore)) != (time.Second * 5) {
		t.Errorf("Invalid certificate expiry")
	}

	foundCertDER := false
	foundRenewCount := false
	var origCertDER []byte
	var renewCount int64 = 0
	for _, ext := range certClient1.Extensions {
		if ext.Id.Equal(oidOriginalCertificate) {
			origCertDER = ext.Value
			foundCertDER = true
		} else if ext.Id.Equal(oidRenewCount) {
			asn1.Unmarshal(ext.Value, &renewCount)
			foundRenewCount = true
		}
	}

	if !(foundRenewCount && foundCertDER) {
		t.Errorf("Not found certDER or renewCount Extensions")
	}

	if !bytes.Equal(origCertDER, clientCert.Raw) {
		t.Errorf("Extension not Matching old cert")
	}

	if renewCount != 1 {
		t.Errorf("Extension renew count is wrong")
	}

	clientCerts = [][]byte{certClient1.Raw}
	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		t.Errorf("failed to verify certificate: " + err.Error())
	}
	if _, err = tls.X509KeyPair(EncodeCertPEM(certClient1), EncodePrivateKeyPEM(keyClient1)); err != nil {
		t.Errorf("Error Verifying key and cert: %s", err.Error())
	}

	// ================= Renew 2 ========================
	oldcert, err = tls.X509KeyPair(EncodeCertPEM(certClient1), EncodePrivateKeyPEM(keyClient1))
	if err != nil {
		t.Errorf("Error creating X509 keypair: %s", err.Error())
	}
	csr2, keyClient2Pem, err := GenerateCertificateRenewRequest(&oldcert)
	if err != nil {
		t.Errorf("Error creating renew CSR: %s", err.Error())
	}
	keyClient2, err := DecodePrivateKeyPEM(keyClient2Pem)
	if err != nil {
		t.Errorf("Failed Decoding privatekey: %s", err.Error())
	}
	certClient2Pem, err := caAuth.SignRequest(csr2, certClient1.Raw, nil)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}
	certClient2, err := DecodeCertPEM(certClient2Pem)
	if err != nil {
		t.Errorf("Failed Decoding cert: %s", err.Error())
	}
	// Test certificate duration
	if (certClient2.NotAfter.Sub(certClient2.NotBefore)) != (time.Second * 5) {
		t.Errorf("Invalid certificate expiry")
	}

	foundCertDER = false
	foundRenewCount = false
	for _, ext := range certClient2.Extensions {
		if ext.Id.Equal(oidOriginalCertificate) {
			origCertDER = ext.Value
			foundCertDER = true
		} else if ext.Id.Equal(oidRenewCount) {
			asn1.Unmarshal(ext.Value, &renewCount)
			foundRenewCount = true
		}
	}

	if !(foundRenewCount && foundCertDER) {
		t.Errorf("Not found certDER or renewCount Extensions")
	}

	// The origCertDER should point to the first cert
	if !bytes.Equal(origCertDER, clientCert.Raw) {
		t.Errorf("Extension not Matching old cert")
	}

	if renewCount != 2 {
		t.Errorf("Extension renew count is wrong")
	}

	clientCerts = [][]byte{certClient2.Raw}
	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		t.Errorf("failed to verify certificate: " + err.Error())
	}
	if _, err = tls.X509KeyPair(EncodeCertPEM(certClient2), EncodePrivateKeyPEM(keyClient2)); err != nil {
		t.Errorf("Error Verifying key and cert: %s", err.Error())
	}
}

func Test_CACertsRenewVerifySameKey(t *testing.T) {
	ca, key, err := GenerateClientCertificate("test CA")
	if err != nil {
		t.Errorf("Error creation in CA certificate failed: %s", err.Error())
	}

	rootSigner, err := tls.X509KeyPair(EncodeCertPEM(ca), EncodePrivateKeyPEM(key))
	if err != nil {
		t.Errorf("Failed to load root key pair: %v", err)
		return
	}

	caConfig := CAConfig{
		RootSigner: &rootSigner,
	}

	caAuth, err := NewCertificateAuthority(&caConfig)
	if err != nil {
		t.Errorf("Error creation CA Auth: %s", err.Error())
	}

	conf := Config{
		CommonName:   "Test Cert",
		Organization: []string{"microsoft"},
	}
	conf.AltNames.DNSNames = []string{"Test Cert"}
	csr, keyClientPem, err := GenerateCertificateRequest(&conf, nil)
	if err != nil {
		t.Errorf("Error creation in CSR: %s", err.Error())
	}
	keyClient, err := DecodePrivateKeyPEM(keyClientPem)
	if err != nil {
		t.Errorf("Failed Decoding privatekey: %s", err.Error())
	}
	signConf := SignConfig{Offset: time.Second * 5}
	clientCertPem, err := caAuth.SignRequest(csr, nil, &signConf)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}
	clientCert, err := DecodeCertPEM(clientCertPem)
	if err != nil {
		t.Errorf("Failed Decoding cert: %s", err.Error())
	}
	// Test certificate duration
	if (clientCert.NotAfter.Sub(clientCert.NotBefore)) != signConf.Offset {
		t.Errorf("Invalid certificate expiry")
	}

	clientCerts := [][]byte{clientCert.Raw}

	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	oldcert, err := tls.X509KeyPair(EncodeCertPEM(clientCert), EncodePrivateKeyPEM(keyClient))
	if err != nil {
		t.Errorf("Error creating X509 keypair: %s", err.Error())
	}

	// ================= Renew 1 ========================
	csr1, err := GenerateCertificateRenewRequestSameKey(&oldcert)
	if err != nil {
		t.Errorf("Error creating renew CSR: %s", err.Error())
	}
	certClient1Pem, err := caAuth.SignRequest(csr1, clientCert.Raw, nil)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	certClient1, err := DecodeCertPEM(certClient1Pem)
	if err != nil {
		t.Errorf("Failed Decoding cert: %s", err.Error())
	}

	// Test certificate duration
	if (certClient1.NotAfter.Sub(certClient1.NotBefore)) != signConf.Offset {
		t.Errorf("Invalid certificate expiry")
	}

	foundCertDER := false
	foundRenewCount := false
	var origCertDER []byte
	var renewCount int64 = 0
	for _, ext := range certClient1.Extensions {
		if ext.Id.Equal(oidOriginalCertificate) {
			origCertDER = ext.Value
			foundCertDER = true
		} else if ext.Id.Equal(oidRenewCount) {
			asn1.Unmarshal(ext.Value, &renewCount)
			foundRenewCount = true
		}
	}

	if !(foundRenewCount && foundCertDER) {
		t.Errorf("Not found certDER or renewCount Extensions")
	}

	if !bytes.Equal(origCertDER, clientCert.Raw) {
		t.Errorf("Extension not Matching old cert")
	}

	if renewCount != 1 {
		t.Errorf("Extension renew count is wrong")
	}

	clientCerts = [][]byte{certClient1.Raw}
	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		t.Errorf("failed to verify certificate: " + err.Error())
	}
	if _, err = tls.X509KeyPair(EncodeCertPEM(certClient1), EncodePrivateKeyPEM(keyClient)); err != nil {
		t.Errorf("Error Verifying key and cert: %s", err.Error())
	}

	// ================= Renew 2 ========================
	oldcert, err = tls.X509KeyPair(EncodeCertPEM(certClient1), EncodePrivateKeyPEM(keyClient))
	if err != nil {
		t.Errorf("Error creating X509 keypair: %s", err.Error())
	}
	csr2, err := GenerateCertificateRenewRequestSameKey(&oldcert)
	if err != nil {
		t.Errorf("Error creating renew CSR: %s", err.Error())
	}
	certClient2Pem, err := caAuth.SignRequest(csr2, certClient1.Raw, nil)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	certClient2, err := DecodeCertPEM(certClient2Pem)
	if err != nil {
		t.Errorf("Failed Decoding cert: %s", err.Error())
	}
	// Test certificate duration
	if (certClient2.NotAfter.Sub(certClient2.NotBefore)) != signConf.Offset {
		t.Errorf("Invalid certificate expiry")
	}

	foundCertDER = false
	foundRenewCount = false
	for _, ext := range certClient2.Extensions {
		if ext.Id.Equal(oidOriginalCertificate) {
			origCertDER = ext.Value
			foundCertDER = true
		} else if ext.Id.Equal(oidRenewCount) {
			asn1.Unmarshal(ext.Value, &renewCount)
			foundRenewCount = true
		}
	}

	if !(foundRenewCount && foundCertDER) {
		t.Errorf("Not found certDER or renewCount Extensions")
	}

	// The origCertDER should point to the first cert
	if !bytes.Equal(origCertDER, clientCert.Raw) {
		t.Errorf("Extension not Matching old cert")
	}

	if renewCount != 2 {
		t.Errorf("Extension renew count is wrong")
	}

	clientCerts = [][]byte{certClient2.Raw}
	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		t.Errorf("failed to verify certificate: " + err.Error())
	}
	if _, err = tls.X509KeyPair(EncodeCertPEM(certClient2), EncodePrivateKeyPEM(keyClient)); err != nil {
		t.Errorf("Error Verifying key and cert: %s", err.Error())
	}
}
