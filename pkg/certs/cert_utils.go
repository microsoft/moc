// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package certs

import (
	"fmt"
	"time"

	"github.com/microsoft/moc/pkg/errors"
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
