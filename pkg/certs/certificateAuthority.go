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
	"math"
	"math/big"
	"time"

	"github.com/microsoft/moc/pkg/errors"
)

var (
	//  1.3.6.1.4.1.311.104  subtree is defined for CIA MSK8S
	oidRenewCertificates   = []int{1, 3, 6, 1, 4, 1, 311, 104, 1, 1}
	oidOriginalCertificate = []int{1, 3, 6, 1, 4, 1, 311, 104, 1, 2}
	oidRenewCount          = []int{1, 3, 6, 1, 4, 1, 311, 104, 1, 3}

	// RFC 5755
	OidAccessIdentity = []int{1, 3, 6, 1, 5, 5, 7, 10, 2}
)

type Revocation interface {
	IsRevoked(cert *x509.Certificate) error
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
		return certs, errors.Wrapf(errors.InvalidInput, "data does not contain any valid certificates")
	}
	return certs, nil
}

// NewCertificateAuthority creates a CertificateAuthority
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
			return nil, errors.Wrapf(errors.Failed, "unable to parse rootSigner: %v", err)
		}
	}

	ca.rootsPool = x509.NewCertPool()
	ca.rootsPool.AddCert(ca.rootCert)

	for _, cert := range config.AdditionalRoots {
		ca.rootsPool.AddCert(cert)
	}

	return &ca, nil
}

// VerifyClientCertificate verifies rawCerts(ASN encoded) using the CertificateAuthority
func (ca *CertificateAuthority) VerifyClientCertificate(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.Wrapf(errors.InvalidInput, "Certificate list empty, nothing to verify")
	}
	certs := []*x509.Certificate{}
	for _, rawcert := range rawCerts {
		cert, err := x509.ParseCertificate(rawcert)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
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
		return errors.Wrapf(err, "unable to verify client certificate")
	}

	if ca.revocation != nil {
		if err = ca.revocation.IsRevoked(leaf); err != nil {
			return errors.Wrapf(err, "certificate is revoked")
		}
	}

	return nil
}

// SignRequest signs the CSR using Certificate Authority
// if oldCertPem is provided it is validated against CA
func (ca *CertificateAuthority) SignRequest(csrPem []byte, oldCertPem []byte, conf *SignConfig) (retCert []byte, err error) {

	csr, err := DecodeCertRequestPEM(csrPem)
	if err != nil {
		return
	}
	var oldCert *x509.Certificate
	if oldCertPem != nil || len(oldCertPem) != 0 {
		if err = ca.VerifyClientCertificate([][]byte{oldCertPem}); err != nil {
			return nil, errors.Wrapf(errors.InvalidInput, "Old certificate not signed by the CA authority : %v", err)
		}
		oldCert, err = DecodeCertPEM(oldCertPem)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, errors.Wrapf(errors.InvalidInput, "Invalid CSR signature: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}

	offset := (time.Hour * 24 * 365)
	accessIdentity := []byte{}
	if conf != nil {
		offset = conf.Offset
		accessIdentity = []byte(conf.Identity)
	}
	now := time.Now().UTC()

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(offset), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}

	csrRenewCertsPEM := []byte{}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidRenewCertificates) {
			csrRenewCertsPEM = ext.Value
			break
		}
	}

	if len(csrRenewCertsPEM) != 0 {

		csrRenewCert, err := parseCertsPEM(csrRenewCertsPEM)
		if err != nil || len(csrRenewCert) < 2 {
			return nil, errors.Wrapf(errors.InvalidInput, "missing CSR renew certificates")
		}

		// csrRenewCert[0] is signed by csrRenewCert[1]
		// csrRenewCert[1] is cert to be renewed
		// csrRenewCert[2] ... optional intermediate certificates to verify csrRenewCert

		certToRenew := csrRenewCert[1]

		// The certToRenew must also be used as the clientAuthCert
		if oldCert != nil {
			if !bytes.Equal(certToRenew.Raw, oldCert.Raw) {
				return nil, errors.Wrapf(errors.InvalidInput, "certToRenew wasn't used for clientAuthCert")
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
				return nil, errors.Wrapf(errors.Expired, "unable to verify certificate to be renewed: Certificate Expired: %v", err)
			} else {
				return nil, errors.Wrapf(errors.Failed, "unable to verify certificate to be renewed: %v", err)
			}
		}

		err = certToRenew.CheckSignature(csrRenewCert[0].SignatureAlgorithm,
			csrRenewCert[0].RawTBSCertificate, csrRenewCert[0].Signature)
		if err != nil {
			return nil, errors.Wrapf(errors.Failed, "unable to verify signature of CSR Key certificate: %v", err)
		}

		// Check that the public key in the CSR matches the public key in the CSR Key certificate
		if !bytes.Equal(csr.RawSubjectPublicKeyInfo, csrRenewCert[0].RawSubjectPublicKeyInfo) {
			return nil, errors.Wrapf(errors.Failed, "public key in CSR and CSR Key certificate don't match")
		}

		if ca.revocation != nil {
			if err = ca.revocation.IsRevoked(certToRenew); err != nil {
				return nil, errors.Wrapf(err, "certificate is revoked")
			}
		}

		// We can now use the content from the certificate to be renewed
		template = *certToRenew

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
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       OidAccessIdentity,
		Critical: false,
		Value:    accessIdentity,
	})
	cert, err := x509.CreateCertificate(rand.Reader, &template, ca.rootCert, csr.PublicKey, ca.rootSigner.PrivateKey)
	if err != nil {
		return
	}

	x509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return
	}
	retCert = EncodeCertPEM(x509Cert)
	return
}
