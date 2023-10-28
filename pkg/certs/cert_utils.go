// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/microsoft/moc/pkg/errors"
	wssdnet "github.com/microsoft/moc/pkg/net"
)

const (
	// formatSHA256 is the prefix for pins that are full-length SHA-256 hashes encoded in base 16 (hex)
	formatSHA256 = "sha256"
)

type backOffFactor struct {
	renewBackoffFactor float64
	errorBackoffFactor float64
}

type backOffDuration struct {
	RenewBackoffDuration time.Duration
	ErrorBackoffDuration time.Duration
}

func NewBackOffFactor(renewBackoffFactor, errorBackoffFactor float64) (factor *backOffFactor, err error) {
	if renewBackoffFactor <= 0 {
		return nil, errors.Wrapf(errors.InvalidInput, "Factor renewBackoffFactor(%f) cannot be <= 0.0", renewBackoffFactor)
	}
	if errorBackoffFactor <= 0 {
		return nil, errors.Wrapf(errors.InvalidInput, "Factor errorBackoffFactor(%f) cannot be <= 0.0", errorBackoffFactor)
	}
	return &backOffFactor{renewBackoffFactor: renewBackoffFactor, errorBackoffFactor: errorBackoffFactor}, nil
}

func calculateTime(before, after, now time.Time, factor *backOffFactor) (duration *backOffDuration) {
	validity := after.Sub(before)

	errorBackoff := time.Duration(float64(validity.Nanoseconds()) * factor.errorBackoffFactor)

	tresh := time.Duration(float64(validity.Nanoseconds()) * factor.renewBackoffFactor)

	treshNotAfter := after.Add(-tresh)
	return &backOffDuration{RenewBackoffDuration: treshNotAfter.Sub(now), ErrorBackoffDuration: errorBackoff}
}

func CalculateRenewTime(certificate string, factor *backOffFactor) (duration *backOffDuration, err error) {

	x509Cert, err := DecodeCertPEM([]byte(certificate))
	if err != nil {
		return
	}
	fmt.Println("factor", factor)
	return calculateTime(x509Cert.NotBefore, x509Cert.NotAfter, time.Now(), factor), nil
}

func IsCertificateExpired(certificate string) (bool, error) {
	x509Cert, err := DecodeCertPEM([]byte(certificate))
	if err != nil {
		return false, err
	}
	return x509Cert.NotAfter.Before(time.Now()), nil
}

func GenerateExpiredClientCertificate(name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, key, err
	}

	nodeFqdn, err := wssdnet.GetIPAddress()
	if err != nil {
		return nil, key, err
	}

	now := time.Now().UTC()

	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, key, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"microsoft"},
		},
		NotBefore:             now.Add(-time.Hour * 24 * 365 * 2), // 2 years ago
		NotAfter:              now.Add(-time.Hour * 24 * 365),     // 1 year ago
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{wssdnet.StringToNetIPAddress(wssdnet.LOOPBACK_ADDRESS), wssdnet.StringToNetIPAddress(nodeFqdn)},
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
