// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package certs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/microsoft/moc/pkg/errors"

	gomock "github.com/golang/mock/gomock"
	mock "github.com/microsoft/moc/pkg/certs/mock"
	"github.com/microsoft/moc/rpc/testagent"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func IsTransportUnavailable(err error) bool {
	if e, ok := status.FromError(err); ok && e.Code() == codes.Unavailable {
		return true
	}
	return false
}

type TestTlsServer struct {
}

func (s *TestTlsServer) PingHello(ctx context.Context, in *testagent.Hello) (*testagent.Hello, error) {
	return &testagent.Hello{Name: "Hello From the Server!" + in.Name}, nil
}

func startHelloServer(grpcServer *grpc.Server, address string) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	tlsServer := TestTlsServer{}
	testagent.RegisterHelloAgentServer(grpcServer, &tlsServer)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

type CertAuthority struct {
	ca *CertificateAuthority
}

func (auth *CertAuthority) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return auth.ca.VerifyClientCertificate(rawCerts)
}

func getTlsCreds(t *testing.T, tlsCert tls.Certificate, certAuth *CertAuthority) credentials.TransportCredentials {

	return credentials.NewTLS(&tls.Config{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequestClientCert,
		Certificates:             []tls.Certificate{tlsCert},
		VerifyPeerCertificate:    certAuth.VerifyPeerCertificate,
	})
}

func getGrpcServer(t *testing.T, creds credentials.TransportCredentials) *grpc.Server {
	var opts []grpc.ServerOption
	opts = append(opts, grpc.Creds(creds))
	grpcServer := grpc.NewServer(opts...)
	return grpcServer
}

func makeTlsCall(t *testing.T, address string, provider credentials.TransportCredentials) (*testagent.Hello, error) {
	var conn *grpc.ClientConn
	var err error
	if provider != nil {
		conn, err = grpc.Dial(address, grpc.WithTransportCredentials(provider))
	} else {
		conn, err = grpc.Dial(address, grpc.WithInsecure())
	}
	assert.NoErrorf(t, err, "Failed to dial", err)
	defer conn.Close()
	c := testagent.NewHelloAgentClient(conn)
	return c.PingHello(context.Background(), &testagent.Hello{Name: "TLSServer"})
}

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

func NewTransportCredentialFromAuthFromPem(serverName string, tlsCert tls.Certificate, caCertPem []byte) (credentials.TransportCredentials, error) {
	certPool := x509.NewCertPool()
	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(caCertPem); !ok {
		return nil, fmt.Errorf("could not append the server certificate")
	}
	creds := &tls.Config{
		ServerName:   serverName,
		RootCAs:      certPool,
		Certificates: []tls.Certificate{tlsCert},
	}
	return credentials.NewTLS(creds), nil
}

func Test_TLSServer(t *testing.T) {
	server := "localhost"
	port := "9000"
	address := server + ":" + port
	ca, key, err := GenerateClientCertificate("test CA")
	assert.NoErrorf(t, err, "Error creation in CA certificate failed: %v", err)

	rootSigner, err := tls.X509KeyPair(EncodeCertPEM(ca), EncodePrivateKeyPEM(key))
	assert.NoErrorf(t, err, "Failed to load root key pair: %v", err)

	caConfig := CAConfig{
		RootSigner: &rootSigner,
	}

	caAuth, err := NewCertificateAuthority(&caConfig)
	assert.NoErrorf(t, err, "Error creation CA Auth: %v", err)

	certPem := EncodeCertPEM(ca)
	keyPem := EncodePrivateKeyPEM(key)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to get tls cert", err)

	creds := getTlsCreds(t, tlsCert, &CertAuthority{caAuth})
	grpcServer := getGrpcServer(t, creds)
	go startHelloServer(grpcServer, address)
	defer grpcServer.Stop()
	time.Sleep((time.Second * 3))
	conf := Config{
		CommonName:   "Test Cert",
		Organization: []string{"microsoft"},
	}
	conf.AltNames.DNSNames = []string{"Test Cert"}
	csr, keyClientPem, err := GenerateCertificateRequest(&conf, nil)
	assert.NoErrorf(t, err, "Error creation in CSR: %v", err)

	signConf := SignConfig{Offset: time.Second * 5}
	clientCertPem, err := caAuth.SignRequest(csr, nil, &signConf)
	assert.NoErrorf(t, err, "Error signing CSR: %v", err)
	tlsClientCert, err := tls.X509KeyPair(clientCertPem, keyClientPem)
	assert.NoErrorf(t, err, "Failed to get tls cert", err)

	provider, err := NewTransportCredentialFromAuthFromPem(server, tlsClientCert, EncodeCertPEM(ca))
	assert.NoErrorf(t, err, "Failed to create TLS Credentials", err)
	// Making the certificate invalid
	time.Sleep((time.Second * 10))
	_, err = makeTlsCall(t, address, provider)
	assert.True(t, IsTransportUnavailable(err))
}

func Test_CACerts(t *testing.T) {
	ca, key, err := GenerateClientCertificate("test CA")
	assert.NoErrorf(t, err, "Error creation in CA certificate failed: %v", err)

	rootSigner, err := tls.X509KeyPair(EncodeCertPEM(ca), EncodePrivateKeyPEM(key))
	assert.NoErrorf(t, err, "Failed to load root key pair: %v", err)

	caConfig := CAConfig{
		RootSigner: &rootSigner,
	}
	caAuth, err := NewCertificateAuthority(&caConfig)
	assert.NoErrorf(t, err, "Error creation CA Auth: %v", err)

	conf := Config{
		CommonName:   "Test Cert",
		Organization: []string{"microsoft"},
	}
	conf.AltNames.DNSNames = []string{"Test Cert"}
	csr, keyClientPem, err := GenerateCertificateRequest(&conf, nil)
	assert.NoErrorf(t, err, "Error creation in CSR: %v", err)
	keyClient, err := DecodePrivateKeyPEM(keyClientPem)
	assert.NoErrorf(t, err, "Failed Decoding privatekey: %v", err)
	clientCertPem, err := caAuth.SignRequest(csr, nil, nil)
	assert.NoErrorf(t, err, "Error signing CSR: %v", err)
	clientCert, err := DecodeCertPEM(clientCertPem)
	assert.NoErrorf(t, err, "Failed Decoding cert: %v", err)
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
	assert.NoErrorf(t, err, "Error creation in CA certificate failed: %v", err)

	rootSigner, err := tls.X509KeyPair(EncodeCertPEM(ca), EncodePrivateKeyPEM(key))
	assert.NoErrorf(t, err, "Failed to load root key pair: %v", err)

	caConfig := CAConfig{
		RootSigner: &rootSigner,
	}

	caAuth, err := NewCertificateAuthority(&caConfig)
	assert.NoErrorf(t, err, "Error creation CA Auth: %v", err)

	conf := Config{
		CommonName:   "Test Cert",
		Organization: []string{"microsoft"},
	}
	conf.AltNames.DNSNames = []string{"Test Cert"}
	csr, keyClientPem, err := GenerateCertificateRequest(&conf, nil)
	assert.NoErrorf(t, err, "Error creation in CSR: %v", err)
	keyClient, err := DecodePrivateKeyPEM(keyClientPem)
	assert.NoErrorf(t, err, "Failed Decoding privatekey: %v", err)

	signConf := SignConfig{Offset: time.Second * 5}
	clientCertPem, err := caAuth.SignRequest(csr, nil, &signConf)
	assert.NoErrorf(t, err, "Error signing CSR: %v", err)

	clientCert, err := DecodeCertPEM(clientCertPem)
	assert.NoErrorf(t, err, "Failed Decoding cert: %v", err)

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

	err = caAuth.VerifyClientCertificate(clientCerts)
	assert.NoErrorf(t, err, "failed to verify certificate: %v", err)

	time.Sleep(time.Second * 6)
	err = caAuth.VerifyClientCertificate(clientCerts)
	assert.Errorf(t, err, "failed to verify certificate after Expiry")

	_, err = tls.X509KeyPair(EncodeCertPEM(clientCert), EncodePrivateKeyPEM(keyClient))
	assert.NoErrorf(t, err, "Error Verifying key and cert: %v", err)
}

func Test_CACertsRenewVerify(t *testing.T) {
	ca, key, err := GenerateClientCertificate("test CA")
	assert.NoErrorf(t, err, "Error creation in CA certificate failed: %v", err)

	rootSigner, err := tls.X509KeyPair(EncodeCertPEM(ca), EncodePrivateKeyPEM(key))
	assert.NoErrorf(t, err, "Failed to load root key pair: %v", err)

	caConfig := CAConfig{
		RootSigner: &rootSigner,
	}
	caAuth, err := NewCertificateAuthority(&caConfig)
	assert.NoErrorf(t, err, "Error creation CA Auth: %v", err)

	conf := Config{
		CommonName:   "Test Cert",
		Organization: []string{"microsoft"},
	}
	conf.AltNames.DNSNames = []string{"Test Cert"}
	csr, keyClientPem, err := GenerateCertificateRequest(&conf, nil)
	assert.NoErrorf(t, err, "Error creation in CSR: %v", err)

	keyClient, err := DecodePrivateKeyPEM(keyClientPem)
	assert.NoErrorf(t, err, "Failed Decoding privatekey: %v", err)

	signConf := SignConfig{Offset: time.Second * 5}
	clientCertPem, err := caAuth.SignRequest(csr, nil, &signConf)
	assert.NoErrorf(t, err, "Error signing CSR: %v", err)

	clientCert, err := DecodeCertPEM(clientCertPem)
	assert.NoErrorf(t, err, "Failed Decoding cert: %v", err)

	// Test certificate duration
	if (clientCert.NotAfter.Sub(clientCert.NotBefore)) != signConf.Offset {
		t.Errorf("Invalid certificate expiry")
	}

	clientCerts := [][]byte{clientCert.Raw}

	err = caAuth.VerifyClientCertificate(clientCerts)
	assert.NoErrorf(t, err, "Failed to verify certificate: %v", err)

	oldcert, err := tls.X509KeyPair(EncodeCertPEM(clientCert), EncodePrivateKeyPEM(keyClient))
	assert.NoErrorf(t, err, "Error creating X509 keypair: %v", err)

	// ================= Renew 1 ========================
	csr1, keyClient1Pem, err := GenerateCertificateRenewRequest(&oldcert)
	assert.NoErrorf(t, err, "Error creating renew CSR: %v", err)

	keyClient1, err := DecodePrivateKeyPEM(keyClient1Pem)
	assert.NoErrorf(t, err, "Failed Decoding privatekey: %v", err)

	signConf = SignConfig{Offset: time.Second * 20}
	certClient1Pem, err := caAuth.SignRequest(csr1, clientCert.Raw, &signConf)
	assert.NoErrorf(t, err, "Error signing CSR: %v", err)

	certClient1, err := DecodeCertPEM(certClient1Pem)
	assert.NoErrorf(t, err, "Failed Decoding cert: %v", err)

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
	err = caAuth.VerifyClientCertificate(clientCerts)
	assert.NoErrorf(t, err, "failed to verify certificate: %v", err)
	_, err = tls.X509KeyPair(EncodeCertPEM(certClient1), EncodePrivateKeyPEM(keyClient1))
	assert.NoErrorf(t, err, "Error Verifying key and cert: %v", err)

	// ================= Renew 2 ========================
	oldcert, err = tls.X509KeyPair(EncodeCertPEM(certClient1), EncodePrivateKeyPEM(keyClient1))
	assert.NoErrorf(t, err, "Error creating X509 keypair: %v", err)

	csr2, keyClient2Pem, err := GenerateCertificateRenewRequest(&oldcert)
	assert.NoErrorf(t, err, "Error creating renew CSR: %v", err)

	keyClient2, err := DecodePrivateKeyPEM(keyClient2Pem)
	assert.NoErrorf(t, err, "Failed Decoding privatekey: %v", err)

	certClient2Pem, err := caAuth.SignRequest(csr2, certClient1.Raw, nil)
	assert.NoErrorf(t, err, "Error signing CSR: %v", err)
	certClient2, err := DecodeCertPEM(certClient2Pem)
	assert.NoErrorf(t, err, "Failed Decoding cert: %v", err)

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
	err = caAuth.VerifyClientCertificate(clientCerts)
	assert.NoErrorf(t, err, "failed to verify certificate: %v", err)
	_, err = tls.X509KeyPair(EncodeCertPEM(certClient2), EncodePrivateKeyPEM(keyClient2))
	assert.NoErrorf(t, err, "Error Verifying key and cert: %v", err)
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
		t.Errorf("failed to verify certificate: %s", err.Error())
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
		t.Errorf("failed to verify certificate: %s", err.Error())
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
	if duration.RenewBackoffDuration > time.Duration(time.Second*4) || duration.RenewBackoffDuration < time.Duration(time.Second*1) {
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
	if duration.RenewBackoffDuration > time.Duration(time.Second*6) || duration.RenewBackoffDuration < time.Duration(time.Second*3) {
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
	if duration.RenewBackoffDuration > time.Duration(time.Second*-10) || duration.RenewBackoffDuration < time.Duration(time.Second*-13) {
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
	if duration.RenewBackoffDuration > time.Duration(time.Second*-13) || duration.RenewBackoffDuration < time.Duration(time.Second*-16) {
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
