// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/microsoft/moc/pkg/errors"

	gomock "github.com/golang/mock/gomock"
	mock "github.com/microsoft/moc/pkg/certs/mock"
)

func createTestCertificate(before, after time.Time) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return "", err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "test",
			Organization: []string{"microsoft"},
		},
		NotBefore:             before,
		NotAfter:              after,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		IsCA:                  true,
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return "", err
	}

	x509Cert, err := x509.ParseCertificate(b)
	if err != nil {
		return "", err
	}

	pemCert := EncodeCertPEM(x509Cert)
	return string(pemCert), nil
}

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
		Roots:     roots,
		DNSName:   "Test Cert",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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

func Test_BackoffFactor(t *testing.T) {
	_, err := NewBackOffFactor(-1.0, 5)
	if err == nil || !errors.IsInvalidInput(err) {
		t.Errorf("Expected Error InvalidInput")
	}
	_, err = NewBackOffFactor(1.0, -5.0)
	if err == nil || !errors.IsInvalidInput(err) {
		t.Errorf("Expected Error InvalidInput")
	}
	_, err = NewBackOffFactor(-1.0, -5.0)
	if err == nil || !errors.IsInvalidInput(err) {
		t.Errorf("Expected Error InvalidInput")
	}
}

func Test_BackoffFactor1(t *testing.T) {
	factor, err := NewBackOffFactor(1.0, 5)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	if factor.errorBackoffFactor != 5 || factor.renewBackoffFactor != 1 {
		t.Errorf("renewBackoffFactor Expected:1.0 Actual:%f \n errorBackoffFactor Expected:5.0 Actual:%f", factor.renewBackoffFactor, factor.errorBackoffFactor)
	}
}

func Test_CalculateTime(t *testing.T) {
	factor, err := NewBackOffFactor(0.3, 0.02)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -10))
	after := now.Add(time.Duration(time.Second * 10))
	duration := calculateTime(before, after, now, factor)
	if duration.RenewBackoffDuration != time.Duration(time.Second*4) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*4), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration < time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected greater than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*400) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateTime1(t *testing.T) {
	factor, err := NewBackOffFactor(0.1, 0.002)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -30))
	after := now.Add(time.Duration(time.Second * 10))
	duration := calculateTime(before, after, now, factor)
	if duration.RenewBackoffDuration != time.Duration(time.Second*6) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*6), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration < time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected greater than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*80) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateTime2(t *testing.T) {
	factor, err := NewBackOffFactor(0.5, 0.002)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -30))
	after := now.Add(time.Duration(time.Second * 10))
	duration := calculateTime(before, after, now, factor)
	if duration.RenewBackoffDuration != time.Duration(time.Second*-10) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*-10), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration > time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected greater than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*80) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateTime3(t *testing.T) {
	factor, err := NewBackOffFactor(30.0/100.0, 0.02)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Minute * -5)
	after := now.Add(time.Duration(time.Minute*10 + time.Second*30))
	duration := calculateTime(before, after, now, factor)
	if duration.RenewBackoffDuration != time.Duration(time.Minute*5+time.Second*51) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Minute*5+time.Second*51), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration < time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected greater than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Second*18+time.Millisecond*600) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateTimeNegative(t *testing.T) {
	factor, err := NewBackOffFactor(0.3, 0.02)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -20))
	after := now.Add(time.Duration(time.Second * -10))
	duration := calculateTime(before, after, now, factor)
	if duration.RenewBackoffDuration != time.Duration(time.Second*-13) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*-13), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration > time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected less than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*200) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*200), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateTimeAfter(t *testing.T) {
	factor, err := NewBackOffFactor(0.3, 0.02)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * 10))
	after := now.Add(time.Duration(time.Second * 30))
	duration := calculateTime(before, after, now, factor)
	if duration.RenewBackoffDuration != time.Duration(time.Second*24) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*24), duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*400) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateRenewTime(t *testing.T) {
	factor, err := NewBackOffFactor(0.3, 0.02)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -10))
	after := now.Add(time.Duration(time.Second * 10))
	cert, err := createTestCertificate(before, after)
	if err != nil {
		t.Errorf("Failed creating certificate: %s", err.Error())
	}
	duration, err := CalculateRenewTime(cert, factor)
	if err != nil {
		t.Errorf("Failed calculating Certificate renewal backoff: %s", err.Error())
	}
	if duration.RenewBackoffDuration > time.Duration(time.Second*4) || duration.RenewBackoffDuration < time.Duration(time.Second*2) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*4), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration < time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected greater than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*400) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateRenewTime1(t *testing.T) {
	factor, err := NewBackOffFactor(0.1, 0.002)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -30))
	after := now.Add(time.Duration(time.Second * 10))
	cert, err := createTestCertificate(before, after)
	if err != nil {
		t.Errorf("Failed creating certificate: %s", err.Error())
	}
	duration, err := CalculateRenewTime(cert, factor)
	if err != nil {
		t.Errorf("Failed calculating Certificate renewal backoff: %s", err.Error())
	}
	if duration.RenewBackoffDuration > time.Duration(time.Second*6) || duration.RenewBackoffDuration < time.Duration(time.Second*4) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*6), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration < time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected greater than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*80) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateRenewTime2(t *testing.T) {
	factor, err := NewBackOffFactor(0.5, 0.002)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -30))
	after := now.Add(time.Duration(time.Second * 10))
	cert, err := createTestCertificate(before, after)
	if err != nil {
		t.Errorf("Failed creating certificate: %s", err.Error())
	}
	duration, err := CalculateRenewTime(cert, factor)
	if err != nil {
		t.Errorf("Failed calculating Certificate renewal backoff: %s", err.Error())
	}
	if duration.RenewBackoffDuration > time.Duration(time.Second*-10) || duration.RenewBackoffDuration < time.Duration(time.Second*-12) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*-10), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration > time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected greater than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*80) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateRenewTimeNegative(t *testing.T) {
	factor, err := NewBackOffFactor(0.3, 0.02)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -20))
	after := now.Add(time.Duration(time.Second * -10))
	cert, err := createTestCertificate(before, after)
	if err != nil {
		t.Errorf("Failed creating certificate: %s", err.Error())
	}
	duration, err := CalculateRenewTime(cert, factor)
	if err != nil {
		t.Errorf("Failed calculating Certificate renewal backoff: %s", err.Error())
	}
	if duration.RenewBackoffDuration > time.Duration(time.Second*-13) || duration.RenewBackoffDuration < time.Duration(time.Second*-15) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*-13), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration > time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected less than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*200) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*200), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateRenewTimeAfter(t *testing.T) {
	factor, err := NewBackOffFactor(0.3, 0.02)
	if err != nil {
		t.Errorf("Error creating Factor: %s", err.Error())
	}
	now := time.Now()
	before := now.Add(time.Duration(time.Second * 10))
	after := now.Add(time.Duration(time.Second * 30))
	cert, err := createTestCertificate(before, after)
	if err != nil {
		t.Errorf("Failed creating certificate: %s", err.Error())
	}
	duration, err := CalculateRenewTime(cert, factor)
	if err != nil {
		t.Errorf("Failed calculating Certificate renewal backoff: %s", err.Error())
	}
	if duration.RenewBackoffDuration < time.Duration(time.Second*22) || duration.RenewBackoffDuration > time.Duration(time.Second*24) {
		t.Errorf("Wrong wait time returned Expected %s Actual %s", time.Duration(time.Second*24), duration.RenewBackoffDuration)
	}
	if duration.RenewBackoffDuration < time.Duration(0) {
		t.Errorf("Wrong wait time returned Expected greater than zero %s", duration.RenewBackoffDuration)
	}
	if duration.ErrorBackoffDuration != time.Duration(time.Millisecond*400) {
		t.Errorf("Wrong renewbackoff time returned Expected %s Actual %s", time.Duration(time.Millisecond*400), duration.ErrorBackoffDuration)
	}
}

func Test_CalculateCertExpiry(t *testing.T) {
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -30))
	after := now.Add(time.Duration(time.Second * 10))
	cert, err := createTestCertificate(before, after)
	if err != nil {
		t.Errorf("Failed creating certificate: %s", err.Error())
	}
	expired, err := IsCertificateExpired(cert)
	if err != nil {
		t.Errorf("Failed finding certificate expired: %s", err.Error())
	}

	if expired {
		t.Errorf("Certificate expired")
	}
}

func Test_CalculateCertExpiry1(t *testing.T) {
	now := time.Now()
	before := now.Add(time.Duration(time.Second * -20))
	after := now.Add(time.Duration(time.Second * -10))
	cert, err := createTestCertificate(before, after)
	if err != nil {
		t.Errorf("Failed creating certificate: %s", err.Error())
	}
	expired, err := IsCertificateExpired(cert)
	if err != nil {
		t.Errorf("Failed finding certificate expired: %s", err.Error())
	}

	if !expired {
		t.Errorf("Certificate not expired")
	}
}

func Test_Revocation_IsRevoked(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ca, _, _ := GenerateClientCertificate("test CA")
	m := mock.NewMockRevocation(ctrl)
	m.EXPECT().IsRevoked(ca)
	m.IsRevoked(ca)
}
