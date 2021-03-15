// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"time"

	"github.com/microsoft/moc/pkg/certs"
	"github.com/microsoft/moc/pkg/errors"
	"github.com/microsoft/moc/pkg/marshal"
	"github.com/microsoft/moc/rpc/cloudagent/security"
	"github.com/microsoft/moc/rpc/common"
	"google.golang.org/grpc"
)

const (
	CloudAgentServerPort         int     = 55000
	CertificateValidityThreshold float64 = (30.0 / 100.0)
	DefaultServerContextTimeout          = 10 * time.Minute
)

func getServerEndpoint(serverAddress *string) string {
	return fmt.Sprintf("%s:%d", *serverAddress, CloudAgentServerPort)
}

// getRenewClient returns the renew client to communicate with the wssdcloudagent
func getRenewClient(serverAddress *string, authorizer Authorizer) (security.IdentityAgentClient, error) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(authorizer.WithTransportAuthorization()))
	opts = append(opts, grpc.WithPerRPCCredentials(authorizer.WithRPCAuthorization()))

	conn, err := grpc.Dial(getServerEndpoint(serverAddress), opts...)
	if err != nil {
		log.Fatalf("Unable to get AuthenticationClient. Failed to dial: %v", err)
	}

	return security.NewIdentityAgentClient(conn), nil
}

// fromBase64 converts the base64 encoded cert and key to pem encoded
func fromBase64(cert, key string) (pemCert, pemKey []byte, err error) {
	pemCert, err = marshal.FromBase64(cert)
	if err != nil {
		return
	}
	pemKey, err = marshal.FromBase64(key)
	if err != nil {
		return
	}
	return
}

// renewRequired check the cert is it needs a renewal
// If the certificate is within threshold time the renewal is required.
func renewRequired(x509Cert *x509.Certificate) bool {
	validity := x509Cert.NotAfter.Sub(x509Cert.NotBefore)

	// Threshold to renew is 30% of validity
	thresholdDuration := time.Duration(float64(validity.Nanoseconds()) * CertificateValidityThreshold)

	thresholdTime := time.Now().Add(thresholdDuration)
	if x509Cert.NotAfter.After(thresholdTime) {
		return false
	}
	return true
}

// accessFiletoRenewClient creates a renew client from wssdconfig and server
func accessFiletoRenewClient(server string, wssdConfig *WssdConfig) (security.IdentityAgentClient, error) {
	serverPem, tlsCert, err := AccessFileToTls(*wssdConfig)
	if err != nil {
		return nil, err
	}

	authorizer, err := NewAuthorizerFromInput(tlsCert, serverPem, server)
	if err != nil {
		return nil, err
	}

	return getRenewClient(&server, authorizer)
}

// renewCertificate renews the cert and key in wssdconfig.
// If it is to early for renewal the same cert and key are returned in the wssdconfig
func renewCertificate(server string, wssdConfig *WssdConfig) (retConfig *WssdConfig, renewed bool, err error) {
	renewed = false
	pemCert, pemKey, err := fromBase64(wssdConfig.ClientCertificate, wssdConfig.ClientKey)
	if err != nil {
		return
	}

	x509Cert, err := certs.DecodeCertPEM([]byte(pemCert))
	if err != nil {
		return
	}

	if !renewRequired(x509Cert) {
		return wssdConfig, renewed, nil
	}

	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return
	}
	newCsr, newKey, err := certs.GenerateCertificateRenewRequest(&tlsCert)
	if err != nil {
		return
	}

	csr := &security.CertificateSigningRequest{
		Name:           x509Cert.Subject.CommonName,
		Csr:            string(newCsr),
		OldCertificate: wssdConfig.ClientCertificate,
	}

	renewRequest := &security.IdentityCertificateRequest{
		OperationType: common.IdentityCertificateOperation_RENEW_CERTIFICATE,
		IdentityName:  wssdConfig.IdentityName,
		CSR:           []*security.CertificateSigningRequest{csr},
	}
	authClient, err := accessFiletoRenewClient(server, wssdConfig)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServerContextTimeout)
	defer cancel()
	response, err := authClient.OperateCertificates(ctx, renewRequest)
	if err != nil {
		return
	}
	if len(response.Certificates) == 0 {
		return nil, false, errors.Wrapf(errors.NotFound, "Missing certificates from renewal response")
	}
	renewed = true

	newWssdConfig := &WssdConfig{
		CloudCertificate:      wssdConfig.CloudCertificate,
		ClientCertificate:     marshal.ToBase64(response.Certificates[0].NewCertificate),
		ClientKey:             marshal.ToBase64(string(newKey)),
		ClientCertificateType: wssdConfig.ClientCertificateType,
		IdentityName:          wssdConfig.IdentityName,
	}
	return newWssdConfig, renewed, nil
}

// renewCertificates picks the wssdconfig from the location performs a renewal if close to expiry and stores the same back to the location
func RenewCertificates(server string, wssdConfigLocation string) error {
	accessFile := WssdConfig{}
	err := marshal.FromJSONFile(wssdConfigLocation, &accessFile)
	if err != nil {
		return err
	}
	if accessFile.ClientCertificateType == CASigned {
		retAccessFile, renewed, err := renewCertificate(server, &accessFile)
		if err != nil {
			return err
		}
		if renewed {
			if err = marshal.ToJSONFile(*retAccessFile, wssdConfigLocation); err != nil {
				return err
			}
		}
	}

	return nil
}
