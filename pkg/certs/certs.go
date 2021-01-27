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
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"time"

	wssdnet "github.com/microsoft/moc/pkg/net"
)

// KeyPair holds the raw bytes for a certificate and key.
type KeyPair struct {
	Cert, Key []byte
}

// Config contains the basic fields required for creating a certificate.
type Config struct {
	CommonName   string
	Organization []string
	AltNames     AltNames
	Usages       []x509.ExtKeyUsage
}

// Config contains the basic fields required for signing a certificate.
type SignConfig struct {
	offset time.Duration
}

// AltNames contains the domain names and IP addresses for a cert
type AltNames struct {
	DNSNames []string
	IPs      []net.IP
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// IsValid returns true if both the certificate and key are non-nil.
func (k *KeyPair) IsValid() bool {
	return k.Cert != nil && k.Key != nil
}

// NewPrivateKey creates an RSA private key
func NewPrivateKey() (*rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	return pk, err
}

// EncodeCertPEM returns PEM-endcoded certificate data.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}

// EncodePrivateKeyPEM returns PEM-encoded private key data.
func EncodePrivateKeyPEM(key *rsa.PrivateKey) []byte {
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.EncodeToMemory(&block)
}

// EncodePublicKeyPEM returns PEM-encoded public key data.
func EncodePublicKeyBytePEM(key []byte) ([]byte, error) {
	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	}
	return pem.EncodeToMemory(&block), nil
}

// EncodePublicKeyPEM returns PEM-encoded public key data.
func EncodePublicKeyPEM(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return []byte{}, err
	}
	return EncodePublicKeyBytePEM(der)
}

// DecodeCertPEM attempts to return a decoded certificate or nil
// if the encoded input does not contain a certificate.
func DecodeCertPEM(encoded []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, nil
	}

	return x509.ParseCertificate(block.Bytes)
}

// DecodePrivateKeyPEM attempts to return a decoded key or nil
// if the encoded input does not contain a private key.
func DecodePrivateKeyPEM(encoded []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, nil
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func GenerateClientCertificate(name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, key, err
	}

	nodeFqdn, err := wssdnet.GetIPAddress()
	if err != nil {
		return nil, key, err
	}

	now := time.Now().UTC()

	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"microsoft"},
		},
		NotBefore:             now.Add(time.Minute * -5),
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{wssdnet.StringToNetIPAddress("127.0.0.1"), wssdnet.StringToNetIPAddress(nodeFqdn)},
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, key, err
	}

	x509Cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, key, err
	}

	return x509Cert, key, nil
}

func NewSignedCert(key *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey, conf Config) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   conf.CommonName,
			Organization: conf.Organization,
		},
		NotBefore:             now.Add(time.Minute * -5),
		NotAfter:              now.Add(time.Hour * 24 * 365), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              conf.AltNames.DNSNames,
		IPAddresses:           conf.AltNames.IPs,
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(b)
}

func GenerateCertificateRequest(conf Config) (*x509.CertificateRequest, *rsa.PrivateKey, error) {

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, key, err
	}

	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   conf.CommonName,
			Organization: conf.Organization,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          key.Public(),
		DNSNames:           conf.AltNames.DNSNames,
		IPAddresses:        conf.AltNames.IPs,
	}

	b, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		return nil, key, err
	}

	x509CertReq, err := x509.ParseCertificateRequest(b)
	if err != nil {
		return nil, key, err
	}

	return x509CertReq, key, nil
}

func createCSRRenewExtensions(csrCertificate []byte, currentCertificate [][]byte) (extensions []pkix.Extension, err error) {
	certsBuffer := bytes.Buffer{}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: csrCertificate,
	}

	err = pem.Encode(&certsBuffer, certPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("unable to PEM encode CSR certificate: %v", err)
	}

	for _, cert := range currentCertificate {
		certPEMBlock.Bytes = cert
		err = pem.Encode(&certsBuffer, certPEMBlock)
		if err != nil {
			return nil, fmt.Errorf("unable to PEM encode certificates: %v", err)
		}
	}

	extensions = []pkix.Extension{
		{
			Id:       oidRenewCertificates,
			Critical: false,
			Value:    certsBuffer.Bytes(),
		},
	}

	return extensions, nil
}

func GenerateCertificateRenewRequest(cert *tls.Certificate) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	var err error
	leaf := cert.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse leaf: %v", err)
		}
	}

	var privateKey *rsa.PrivateKey

	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		privateKey, err = rsa.GenerateKey(rand.Reader, pub.Size()*8)
	default:
		err = fmt.Errorf("unsupported public key type: %T", pub)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate private key: %v", err)
	}
	csrKeyTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "CSR Key",
		},
		NotBefore: time.Now(),
		NotAfter:  leaf.NotAfter,
	}

	csrCertificate, err := x509.CreateCertificate(rand.Reader, &csrKeyTemplate, leaf,
		privateKey.Public(), cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create CSR Key certificate: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject:     leaf.Subject,
		DNSNames:    leaf.DNSNames,
		IPAddresses: leaf.IPAddresses,
	}
	template := &csrTemplate

	template.ExtraExtensions, err = createCSRRenewExtensions(csrCertificate, cert.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create CSR renew extensions: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create CSR request: %v", err)
	}

	x509CertReq, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, err
	}

	return x509CertReq, privateKey, nil
}

func GenerateCertificateRenewRequestSameKey(cert *tls.Certificate) (*x509.CertificateRequest, error) {
	var err error
	leaf := cert.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("unable to parse leaf: %v", err)
		}
	}

	csrKeyTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "CSR Key",
		},
		NotBefore:   time.Now(),
		NotAfter:    leaf.NotAfter,
		DNSNames:    leaf.DNSNames,
		IPAddresses: leaf.IPAddresses,
	}

	csrCertificate, err := x509.CreateCertificate(rand.Reader, &csrKeyTemplate, leaf,
		publicKey(cert.PrivateKey), cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create CSR Key certificate: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject:     leaf.Subject,
		DNSNames:    leaf.DNSNames,
		IPAddresses: leaf.IPAddresses,
	}
	template := &csrTemplate

	template.ExtraExtensions, err = createCSRRenewExtensions(csrCertificate, cert.Certificate)
	if err != nil {
		return nil, fmt.Errorf("unable to create CSR renew extensions: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create CSR request: %v", err)
	}

	x509CertReq, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	return x509CertReq, nil
}
