// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package auth

import (
	context "context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/microsoft/moc/pkg/certs"
	"github.com/microsoft/moc/pkg/marshal"
	"google.golang.org/grpc/credentials"
)

const (
	ClientTokenName       = ".token"
	ClientCertName        = "wssd.pem"
	ClientTokenPath       = "WSSD_CLIENT_TOKEN"
	WssdConfigPath        = "WSSD_CONFIG_PATH"
	DefaultWSSDFolder     = ".wssd"
	AccessFileDefaultName = "cloudconfig"
	ServerName            = "ServerName"
)

type WssdConfig struct {
	CloudCertificate  string
	ClientCertificate string
	ClientKey         string
}

type Authorizer interface {
	WithTransportAuthorization() credentials.TransportCredentials
	WithRPCAuthorization() credentials.PerRPCCredentials
}

type ManagedIdentityConfig struct {
	ClientTokenPath string
	WssdConfigPath  string
	ServerName      string
}

type LoginConfig struct {
	Name        string
	Token       string
	Certificate string
}

func (ba *BearerAuthorizer) WithRPCAuthorization() credentials.PerRPCCredentials {
	return ba.tokenProvider
}

func (ba *BearerAuthorizer) WithTransportAuthorization() credentials.TransportCredentials {
	return ba.transportCredentials
}

type JwtTokenProvider struct {
	RawData string `json:"rawdata"`
}

// BearerAuthorizer implements the bearer authorization
type BearerAuthorizer struct {
	tokenProvider        JwtTokenProvider
	transportCredentials credentials.TransportCredentials
}

// NewBearerAuthorizer crates a BearerAuthorizer using the given token provider
func NewBearerAuthorizer(tp JwtTokenProvider, tc credentials.TransportCredentials) *BearerAuthorizer {
	return &BearerAuthorizer{
		tokenProvider:        tp,
		transportCredentials: tc,
	}
}

// EnvironmentSettings contains the available authentication settings.
type EnvironmentSettings struct {
	Values map[string]string
}

func NewAuthorizerFromEnvironment(serverName string) (Authorizer, error) {
	settings, err := GetSettingsFromEnvironment(serverName)
	if err != nil {
		return nil, err
	}
	return settings.GetAuthorizer()
}

func NewAuthorizerFromInput(tlsCert tls.Certificate, serverCertificate []byte, server string) (Authorizer, error) {
	transportCreds := TransportCredentialsFromNode(tlsCert, serverCertificate, server)
	return NewBearerAuthorizer(JwtTokenProvider{}, transportCreds), nil
}

func NewAuthorizerForAuth(tokenString string, certificate string, server string) (Authorizer, error) {

	serverPem, err := marshal.FromBase64(certificate)
	if err != nil {
		return NewBearerAuthorizer(JwtTokenProvider{}, credentials.NewTLS(nil)), fmt.Errorf("could not marshal the server certificate")
	}

	certPool := x509.NewCertPool()
	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(serverPem); !ok {
		return NewBearerAuthorizer(JwtTokenProvider{}, credentials.NewTLS(nil)), fmt.Errorf("could not append the server certificate")
	}
	transportCreds := credentials.NewTLS(&tls.Config{
		ServerName: server,
		RootCAs:    certPool,
	})

	return NewBearerAuthorizer(JwtTokenProvider{tokenString}, transportCreds), nil
}

func GetSettingsFromEnvironment(serverName string) (s EnvironmentSettings, err error) {
	s = EnvironmentSettings{
		Values: map[string]string{},
	}
	s.Values[ClientTokenPath] = getClientTokenLocation()
	s.Values[WssdConfigPath] = GetWssdConfigLocation()

	s.Values[ServerName] = serverName

	return
}

func (settings EnvironmentSettings) GetAuthorizer() (Authorizer, error) {
	return settings.GetManagedIdentityConfig().Authorizer()
}

func (settings EnvironmentSettings) GetManagedIdentityConfig() ManagedIdentityConfig {
	return ManagedIdentityConfig{
		settings.Values[ClientTokenPath],
		settings.Values[WssdConfigPath],
		settings.Values[ServerName],
	}
}

func (mc ManagedIdentityConfig) Authorizer() (Authorizer, error) {

	jwtCreds := TokenProviderFromFile(mc.ClientTokenPath)
	transportCreds := TransportCredentialsFromFile(mc.WssdConfigPath, mc.ServerName)

	return NewBearerAuthorizer(jwtCreds, transportCreds), nil
}

func TokenProviderFromFile(tokenLocation string) JwtTokenProvider {
	data, err := ioutil.ReadFile(tokenLocation)
	if err != nil {
		// Call to open the token file most likely failed do to
		// token not being set. This is expected when the an identity is not yet
		// set. Log and continue
		return JwtTokenProvider{}
	}

	return JwtTokenProvider{string(data)}
}

func TransportCredentialsFromFile(wssdConfigLocation string, server string) credentials.TransportCredentials {
	clientCerts := []tls.Certificate{}
	certPool := x509.NewCertPool()

	serverPem, tlsCert, err := ReadAccessFileToTls(wssdConfigLocation)
	if err == nil {
		clientCerts = append(clientCerts, tlsCert)
		// Append the client certificates from the CA
		if ok := certPool.AppendCertsFromPEM(serverPem); !ok {
			return credentials.NewTLS(&tls.Config{})
		}
	}
	verifyPeerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// This is the for extra verification
		return nil
	}

	return credentials.NewTLS(&tls.Config{
		ServerName:            server,
		Certificates:          clientCerts,
		RootCAs:               certPool,
		VerifyPeerCertificate: verifyPeerCertificate,
	})
}

func ReadAccessFileToTls(accessFileLocation string) ([]byte, tls.Certificate, error) {
	accessFile := WssdConfig{}
	err := marshal.FromJSONFile(accessFileLocation, &accessFile)
	if err != nil {
		return []byte{}, tls.Certificate{}, err
	}
	return AccessFileToTls(accessFile)
}
func TransportCredentialsFromNode(tlsCert tls.Certificate, serverCertificate []byte, server string) credentials.TransportCredentials {

	certPool := x509.NewCertPool()
	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(serverCertificate); !ok {
		return credentials.NewTLS(&tls.Config{})
	}
	verifyPeerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// This is the for extra verification
		return nil
	}

	return credentials.NewTLS(&tls.Config{
		ServerName:            server,
		Certificates:          []tls.Certificate{tlsCert},
		RootCAs:               certPool,
		VerifyPeerCertificate: verifyPeerCertificate,
	})

}

func (c JwtTokenProvider) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": c.RawData,
	}, nil
}

func (c JwtTokenProvider) RequireTransportSecurity() bool {
	return true
}

func getClientTokenLocation() string {
	clientTokenPath := os.Getenv(ClientTokenPath)
	if clientTokenPath == "" {
		wd, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		// Create the default token path and set the
		// env variable
		defaultPath := filepath.Join(wd, DefaultWSSDFolder)
		os.MkdirAll(defaultPath, os.ModePerm)
		clientTokenPath = filepath.Join(defaultPath, ClientTokenName)
		os.Setenv(ClientTokenPath, clientTokenPath)
	}
	return clientTokenPath
}

func GetWssdConfigLocation() string {
	wssdConfigPath := os.Getenv(WssdConfigPath)
	if wssdConfigPath == "" {
		wd, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		// Create the default config path and set the
		// env variable
		defaultPath := filepath.Join(wd, DefaultWSSDFolder)
		os.MkdirAll(defaultPath, os.ModePerm)
		wssdConfigPath = filepath.Join(defaultPath, AccessFileDefaultName)
		os.Setenv(WssdConfigPath, wssdConfigPath)
	}
	return wssdConfigPath
}
func SaveToken(tokenStr string) error {
	return ioutil.WriteFile(
		getClientTokenLocation(),
		[]byte(tokenStr),
		0644)
}

func GenerateClientKey(loginconfig LoginConfig) (string, WssdConfig, error) {
	certBytes, err := marshal.FromBase64(loginconfig.Certificate)
	if err != nil {
		return "", WssdConfig{}, err
	}
	accessFile, err := readAccessFile(GetWssdConfigLocation())
	if err != nil {
		x509CertClient, keyClient, err := certs.GenerateClientCertificate(loginconfig.Name)
		if err != nil {
			return "", WssdConfig{}, err
		}

		certBytesClient := certs.EncodeCertPEM(x509CertClient)
		keyBytesClient := certs.EncodePrivateKeyPEM(keyClient)

		accessFile = WssdConfig{
			CloudCertificate:  "",
			ClientCertificate: marshal.ToBase64(string(certBytesClient)),
			ClientKey:         marshal.ToBase64(string(keyBytesClient)),
		}
	}

	if accessFile.CloudCertificate != "" {
		serverPem, err := marshal.FromBase64(accessFile.CloudCertificate)
		if err != nil {
			return "", WssdConfig{}, err
		}

		if string(certBytes) != string(serverPem) {
			certBytes = append(certBytes, serverPem...)
		}
	}

	accessFile.CloudCertificate = marshal.ToBase64(string(certBytes))
	return accessFile.ClientCertificate, accessFile, nil
}

func PrintAccessFile(accessFile WssdConfig) error {
	return marshal.ToJSONFile(accessFile, GetWssdConfigLocation())
}

func readAccessFile(accessFileLocation string) (WssdConfig, error) {
	accessFile := WssdConfig{}
	err := marshal.FromJSONFile(accessFileLocation, &accessFile)
	if err != nil {
		return WssdConfig{}, err
	}

	return accessFile, nil
}

func AccessFileToTls(accessFile WssdConfig) ([]byte, tls.Certificate, error) {
	serverPem, err := marshal.FromBase64(accessFile.CloudCertificate)
	if err != nil {
		return []byte{}, tls.Certificate{}, err
	}
	clientPem, err := marshal.FromBase64(accessFile.ClientCertificate)
	if err != nil {
		return []byte{}, tls.Certificate{}, err
	}
	keyPem, err := marshal.FromBase64(accessFile.ClientKey)
	if err != nil {
		return []byte{}, tls.Certificate{}, err
	}
	tlsCert, err := tls.X509KeyPair(clientPem, keyPem)
	if err != nil {
		return []byte{}, tls.Certificate{}, err
	}

	return serverPem, tlsCert, nil
}
