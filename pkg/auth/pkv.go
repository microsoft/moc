// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"
)

const (
	// formatSHA256 is the prefix for pins that are full-length SHA-256 hashes encoded in base 16 (hex)
	formatSHA256 = "sha256"
)

type publicKeyVerifier struct {
	pubkeypinSet *Set
}

func NewPublicKeyVerifier() *publicKeyVerifier {
	pkv := &publicKeyVerifier{}
	pkv.pubkeypinSet = NewSet()
	return pkv
}

func (pkv *publicKeyVerifier) Allow(caCertHash string) error {
	return pkv.pubkeypinSet.Allow(caCertHash)
}

// VerifyPeerCertificate is a callback to be used for client verification during the TLS handshake
func (c *publicKeyVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

	x509certs := []*x509.Certificate{}

	for _, crt := range rawCerts {
		x509cert, err := x509.ParseCertificate(crt)
		if err != nil {
			return errors.Wrapf(err, "bad server certificate")
		}
		x509certs = append(x509certs, x509cert)
	}

	err := c.pubkeypinSet.CheckAny(x509certs)
	if err != nil {
		return err
	}
	return nil
}

// NB. This is taken from kubeadm https://github.com/kubernetes/kubernetes/blob/master/cmd/kubeadm/app/util/pubkeypin/pubkeypin.go
// Bringing the moc pkgs are light on dependencies and didn't want to muck that up for a self concerned pkg.
// Also this gives us freedom to tweak to our usecase

// Set is a set of pinned x509 public keys.
type Set struct {
	sha256Hashes map[string]bool
}

// NewSet returns a new, empty PubKeyPinSet
func NewSet() *Set {
	return &Set{make(map[string]bool)}
}

// Allow adds an allowed public key hash to the Set
func (s *Set) Allow(pubKeyHashes ...string) error {
	for _, pubKeyHash := range pubKeyHashes {
		parts := strings.Split(pubKeyHash, ":")
		if len(parts) != 2 {
			return errors.New("invalid public key hash, expected \"format:value\"")
		}
		format, value := parts[0], parts[1]

		switch strings.ToLower(format) {
		case "sha256":
			return s.allowSHA256(value)
		default:
			return errors.Errorf("unknown hash format %q", format)
		}
	}
	return nil
}

// CheckAny checks if at least one certificate matches one of the public keys in the set
func (s *Set) CheckAny(certificates []*x509.Certificate) error {
	var hashes []string

	for _, certificate := range certificates {
		if s.checkSHA256(certificate) {
			return nil
		}

		hashes = append(hashes, Hash(certificate))
	}
	return errors.Errorf("none of the public keys %q are pinned", strings.Join(hashes, ":"))
}

// Hash calculates the SHA-256 hash of the Subject Public Key Information (SPKI)
// object in an x509 certificate (in DER encoding). It returns the full hash as a
// hex encoded string (suitable for passing to Set.Allow).
func Hash(certificate *x509.Certificate) string {
	spkiHash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return formatSHA256 + ":" + strings.ToLower(hex.EncodeToString(spkiHash[:]))
}

// allowSHA256 validates a "sha256" format hash and adds a canonical version of it into the Set
func (s *Set) allowSHA256(hash string) error {
	// validate that the hash is the right length to be a full SHA-256 hash
	hashLength := hex.DecodedLen(len(hash))
	if hashLength != sha256.Size {
		return errors.Errorf("expected a %d byte SHA-256 hash, found %d bytes", sha256.Size, hashLength)
	}

	// validate that the hash is valid hex
	_, err := hex.DecodeString(hash)
	if err != nil {
		return err
	}

	// in the end, just store the original hex string in memory (in lowercase)
	s.sha256Hashes[strings.ToLower(hash)] = true
	return nil
}

// checkSHA256 returns true if the certificate's "sha256" hash is pinned in the Set
func (s *Set) checkSHA256(certificate *x509.Certificate) bool {
	actualHash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	actualHashHex := strings.ToLower(hex.EncodeToString(actualHash[:]))
	return s.sha256Hashes[actualHashHex]
}
