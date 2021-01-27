// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package certs

import (
	"crypto/tls"
	"crypto/x509"
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
	csr, _, err := GenerateCertificateRequest(conf)
	if err != nil {
		t.Errorf("Error creation in CSR: %s", err.Error())
	}

	signConf := SignConfig{offset: time.Second * 5}
	clientCert, err := caAuth.NewSignedCert(csr, signConf)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
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
	csr, _, err := GenerateCertificateRequest(conf)
	if err != nil {
		t.Errorf("Error creation in CSR: %s", err.Error())
	}

	signConf := SignConfig{offset: time.Second * 5}
	clientCert, err := caAuth.NewSignedCert(csr, signConf)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	clientCerts := [][]byte{EncodeCertPEM(clientCert)}

	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

	time.Sleep(time.Second * 6)
	if err = caAuth.VerifyClientCertificate(clientCerts); err == nil {
		panic("failed to verify certificate after Expiry")
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
	csr, keyClient, err := GenerateCertificateRequest(conf)
	if err != nil {
		t.Errorf("Error creation in CSR: %s", err.Error())
	}

	signConf := SignConfig{offset: time.Second * 5}
	clientCert, err := caAuth.NewSignedCert(csr, signConf)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	clientCerts := [][]byte{EncodeCertPEM(clientCert)}

	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	oldcert, err := tls.X509KeyPair(EncodeCertPEM(clientCert), EncodePrivateKeyPEM(keyClient))
	if err != nil {
		t.Errorf("Error creating X509 keypair: %s", err.Error())
	}
	csr1, keyClient1, err := GenerateCertificateRenewRequest(&oldcert)
	if err != nil {
		t.Errorf("Error creating renew CSR: %s", err.Error())
	}
	certClient1, err := caAuth.SignRenewRequest(csr1, clientCert)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	clientCerts = [][]byte{EncodeCertPEM(certClient1)}
	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		t.Errorf("failed to verify certificate: " + err.Error())
	}
	if _, err = tls.X509KeyPair(EncodeCertPEM(certClient1), EncodePrivateKeyPEM(keyClient1)); err != nil {
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
	csr, keyClient, err := GenerateCertificateRequest(conf)
	if err != nil {
		t.Errorf("Error creation in CSR: %s", err.Error())
	}

	signConf := SignConfig{offset: time.Second * 5}
	clientCert, err := caAuth.NewSignedCert(csr, signConf)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	clientCerts := [][]byte{EncodeCertPEM(clientCert)}

	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
	oldcert, err := tls.X509KeyPair(EncodeCertPEM(clientCert), EncodePrivateKeyPEM(keyClient))
	if err != nil {
		t.Errorf("Error creating X509 keypair: %s", err.Error())
	}
	csr1, err := GenerateCertificateRenewRequestSameKey(&oldcert)
	if err != nil {
		t.Errorf("Error creating renew CSR: %s", err.Error())
	}
	certClient1, err := caAuth.SignRenewRequest(csr1, clientCert)
	if err != nil {
		t.Errorf("Error signing CSR: %s", err.Error())
	}

	clientCerts = [][]byte{EncodeCertPEM(certClient1)}
	if err := caAuth.VerifyClientCertificate(clientCerts); err != nil {
		t.Errorf("failed to verify certificate: " + err.Error())
	}
	if _, err = tls.X509KeyPair(EncodeCertPEM(certClient1), EncodePrivateKeyPEM(keyClient)); err != nil {
		t.Errorf("Error Verifying key and cert: %s", err.Error())
	}
}
