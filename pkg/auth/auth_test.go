// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var key *rsa.PrivateKey

func init() {
	os.MkdirAll("/tmp/auth", os.ModePerm)
	key, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func Test_GetWssdConfigLocationName(t *testing.T) {
	path := GetMocConfigLocationName("", "")
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed getting home path %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd/cloudconfig")
	if path != expectedPath {
		t.Errorf("Invalid path when not passed no subfolder or filename Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetWssdConfigLocationNameWithSubfolder(t *testing.T) {
	path := GetMocConfigLocationName("test", "")
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed getting home path %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd/test/cloudconfig")
	if path != expectedPath {
		t.Errorf("Invalid path when not passed no subfolder or filename Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetWssdConfigLocationNameWithSubfolderName(t *testing.T) {
	path := GetMocConfigLocationName("test", "cc")
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed getting home path %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd/test/cc")
	if path != expectedPath {
		t.Errorf("Invalid path when not passed no subfolder or filename Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetWssdConfigLocationNameWithName(t *testing.T) {
	path := GetMocConfigLocationName("", "cc")
	wd, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed getting home path %v", err)
	}
	expectedPath := filepath.Join(wd, ".wssd/cc")
	if path != expectedPath {
		t.Errorf("Invalid path when not passed no subfolder or filename Expected %s Actual %s", expectedPath, path)
	}
}

func Test_GetCertRenewRequired(t *testing.T) {
	now := time.Now().UTC()

	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Second * 10),
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Errorf("Failed creating certificate %v", err)
	}

	x509Cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Errorf("Failed parsing certificate %v", err)
	}
	if renewRequired(x509Cert) {
		t.Errorf("RenewRequired Expected:false Actual:true")
	}
}

func Test_GetCertRenewRequiredExpired(t *testing.T) {
	now := time.Now().UTC()

	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: now.Add(-(time.Second * 10)),
		NotAfter:  now,
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Errorf("Failed creating certificate %v", err)
	}

	x509Cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Errorf("Failed parsing certificate %v", err)
	}
	if !renewRequired(x509Cert) {
		t.Errorf("RenewRequired Expected:true Actual:false")
	}
}

func Test_GetCertRenewRequiredBeforeThreshold(t *testing.T) {
	now := time.Now().UTC()

	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: now.Add(-(time.Second * 6)),
		NotAfter:  now.Add(time.Second * 4),
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Errorf("Failed creating certificate %v", err)
	}

	x509Cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Errorf("Failed parsing certificate %v", err)
	}
	if renewRequired(x509Cert) {
		t.Errorf("RenewRequired Expected:false Actual:true")
	}
}

func Test_GetCertRenewRequiredAfterThreshold(t *testing.T) {
	now := time.Now().UTC()

	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: now.Add(-(time.Second * 8)),
		NotAfter:  now.Add(time.Second * 2),
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Errorf("Failed creating certificate %v", err)
	}

	x509Cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Errorf("Failed parsing certificate %v", err)
	}
	if !renewRequired(x509Cert) {
		t.Errorf("RenewRequired Expected:true Actual:false")
	}
}

func Test_GetCertRenewRequiredDelay(t *testing.T) {
	now := time.Now().UTC()

	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: now.Add(-(time.Second * 6)),
		NotAfter:  now.Add(time.Second * 4),
	}

	b, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Errorf("Failed creating certificate %v", err)
	}

	x509Cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Errorf("Failed parsing certificate %v", err)
	}
	if renewRequired(x509Cert) {
		t.Errorf("RenewRequired Expected:false Actual:true")
	}
	time.Sleep(time.Second * 2)
	if !renewRequired(x509Cert) {
		t.Errorf("RenewRequired Expected:true Actual:false")
	}
}
