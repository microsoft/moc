// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"net"
	"time"

	wssdnet "github.com/microsoft/moc-proto/pkg/net"
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

// AltNames contains the domain names and IP addresses for a cert
type AltNames struct {
	DNSNames []string
	IPs      []net.IP
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
		ExtKeyUsage:           conf.Usages,
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
