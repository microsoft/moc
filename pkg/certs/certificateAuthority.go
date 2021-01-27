// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"time"
)

var (
	//  1.3.6.1.4.1.311.104  subtree is defined for CIA MSK8S
	oidRenewCertificates   = []int{1, 3, 6, 1, 4, 1, 311, 104, 1, 1}
	oidOriginalCertificate = []int{1, 3, 6, 1, 4, 1, 311, 104, 1, 2}
	oidRenewCount          = []int{1, 3, 6, 1, 4, 1, 311, 104, 1, 3}
)

type Revocation interface {
	IsRevoked(cert *x509.Certificate) bool
}

type CAConfig struct {
	RootSigner      *tls.Certificate
	CrossRootCert   *x509.Certificate   // OPTIONAL
	AdditionalRoots []*x509.Certificate // OPTIONAL
	Revocation      Revocation          // OPTIONAL
}

type CertificateAuthority struct {
	rootSigner    *tls.Certificate
	rootCert      *x509.Certificate
	crossRootCert *x509.Certificate
	rootsPool     *x509.CertPool
	revocation    Revocation
}

func parseCertsPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	ok := false
	certs := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		// Only use PEM "CERTIFICATE" blocks without extra headers
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, err
		}

		certs = append(certs, cert)
		ok = true
	}

	if !ok {
		return certs, fmt.Errorf("data does not contain any valid certificates")
	}
	return certs, nil
}

func NewCertificateAuthority(config *CAConfig) (*CertificateAuthority, error) {
	var err error

	ca := CertificateAuthority{
		rootSigner:    config.RootSigner,
		crossRootCert: config.CrossRootCert,
		revocation:    config.Revocation,
	}

	ca.rootCert = ca.rootSigner.Leaf
	if ca.rootCert == nil {
		ca.rootCert, err = x509.ParseCertificate(ca.rootSigner.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("unable to parse rootSigner: %v", err)
		}
	}

	ca.rootsPool = x509.NewCertPool()
	ca.rootsPool.AddCert(ca.rootCert)

	for _, cert := range config.AdditionalRoots {
		ca.rootsPool.AddCert(cert)
	}

	return &ca, nil
}

func (ca *CertificateAuthority) VerifyClientCertificate(rawCerts [][]byte) error {
	certs := []*x509.Certificate{}

	for _, rawCert := range rawCerts {
		cert, err := DecodeCertPEM(rawCert)
		if err != nil {
			return fmt.Errorf("Unable to ASN.1 parse rawCerts: %v", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return fmt.Errorf("No rawCerts")
	}

	// TODO Need more clarification
	intermediatesPool := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			intermediatesPool.AddCert(cert)
		}
	}

	leaf := certs[0]

	// TODO Current Time
	verifyOptions := x509.VerifyOptions{
		Intermediates: intermediatesPool,
		Roots:         ca.rootsPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leaf.Verify(verifyOptions)

	if err != nil {
		return fmt.Errorf("unable to verify client certificate: %v", err)
	}

	return nil
}

func (ca *CertificateAuthority) NewSignedCert(csr *x509.CertificateRequest, conf SignConfig) (*x509.Certificate, error) {
	var err error
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(conf.offset), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, ca.rootCert, csr.PublicKey, ca.rootSigner.PrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(b)
}

func (ca *CertificateAuthority) SignRenewRequest(csr *x509.CertificateRequest, oldCert *x509.Certificate) (*x509.Certificate, error) {
	var err error
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %v", err)
	}

	csrRenewCertsPEM := []byte{}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidRenewCertificates) {
			csrRenewCertsPEM = ext.Value
			break
		}
	}

	if len(csrRenewCertsPEM) == 0 {
		return nil, fmt.Errorf("missing CSR renew certificates extension")
	}

	csrRenewCert, err := parseCertsPEM(csrRenewCertsPEM)
	if err != nil || len(csrRenewCert) < 2 {
		return nil, fmt.Errorf("missing CSR renew certificates")
	}

	// csrRenewCert[0] is signed by csrRenewCert[1]
	// csrRenewCert[1] is cert to be renewed
	// csrRenewCert[2] ... optional intermediate certificates to verify csrRenewCert

	certToRenew := csrRenewCert[1]

	// The certToRenew must also be used as the clientAuthCert
	if oldCert != nil {
		if !bytes.Equal(certToRenew.Raw, oldCert.Raw) {
			return nil, fmt.Errorf("certToRenew wasn't used for clientAuthCert")
		}
	}

	intermediatesPool := x509.NewCertPool()
	if len(csrRenewCert) > 2 {
		for _, cert := range csrRenewCert[2:] {
			intermediatesPool.AddCert(cert)
		}
	}

	verifyOptions := x509.VerifyOptions{
		Intermediates: intermediatesPool,
		Roots:         ca.rootsPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err = certToRenew.Verify(verifyOptions)
	if err != nil {
		if time.Now().After(certToRenew.NotAfter) {
			return nil, fmt.Errorf("unable to verify certificate to be renewed: Certificate Expired: %v", err)
		} else {
			return nil, fmt.Errorf("unable to verify certificate to be renewed: %v", err)
		}
	}

	err = certToRenew.CheckSignature(csrRenewCert[0].SignatureAlgorithm,
		csrRenewCert[0].RawTBSCertificate, csrRenewCert[0].Signature)
	if err != nil {
		return nil, fmt.Errorf("unable to verify signature of CSR Key certificate: %v", err)
	}

	// Check that the public key in the CSR matches the public key in the CSR Key certificate
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, csrRenewCert[0].RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("public key in CSR and CSR Key certificate don't match")
	}

	if ca.revocation != nil && ca.revocation.IsRevoked(certToRenew) {
		return nil, fmt.Errorf("certificate to be renewed is revoked")
	}

	// We can now use the content from the certificate to be renewed
	template := *certToRenew

	// We are intentionally using the serial number from the certificate to be renewed
	// template.SerialNumber

	// We are using the same validity as the certificate being renewed
	validity := template.NotAfter.Sub(template.NotBefore)

	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(validity)
	spkiHash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	template.SubjectKeyId = spkiHash[:]
	template.AuthorityKeyId = nil
	template.SignatureAlgorithm = x509.UnknownSignatureAlgorithm

	origCertDER := certToRenew.Raw
	var renewCount int64 = 0

	for _, ext := range certToRenew.Extensions {
		if ext.Id.Equal(oidOriginalCertificate) {
			origCertDER = ext.Value
		} else if ext.Id.Equal(oidRenewCount) {
			asn1.Unmarshal(ext.Value, &renewCount)
		}
	}

	renewCount++
	renewCountDER, _ := asn1.Marshal(renewCount)

	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       oidOriginalCertificate,
			Critical: false,
			Value:    origCertDER,
		},
		{
			Id:       oidRenewCount,
			Critical: false,
			Value:    renewCountDER,
		},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, ca.rootCert, csr.PublicKey, ca.rootSigner.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create renewed certificate: %v", err)
	}

	return x509.ParseCertificate(cert)
}
