// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package auth

//go:generate mockgen -destination mock/auth_mock.go github.com/microsoft/moc/pkg/auth Authorizer
import (
	context "context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"

	"github.com/microsoft/moc/pkg/config"
	"github.com/microsoft/moc/pkg/marshal"
	"github.com/microsoft/moc/rpc/common"
	"google.golang.org/grpc/credentials"
)

const (
	ServerName = "ServerName"
)

type WssdConfig struct {
	CloudCertificate      string
	ClientCertificate     string
	ClientKey             string
	IdentityName          string
	ClientCertificateType LoginType //Depricated : Needs to cleaned up after removing references
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

type ClientType string

const (
	Admin          ClientType = "Admin"
	BareMetal      ClientType = "BareMetal"
	ControlPlane   ClientType = "ControlPlane"
	ExternalClient ClientType = "ExternalClient"
	LoadBalancer   ClientType = "LoadBalancer"
	Node           ClientType = "Node"
)

type LoginConfig struct {
	Name          string     `json:"name,omitempty"`
	Token         string     `json:"token,omitempty"`
	Certificate   string     `json:"certificate,omitempty"`
	ClientType    ClientType `json:"clienttype,omitempty"`
	CloudFqdn     string     `json:"cloudfqdn,omitempty"`
	CloudPort     int32      `json:"cloudport,omitempty"`
	CloudAuthPort int32      `json:"cloudauthport,omitempty"`
	Location      string     `json:"location,omitempty"`
	Type          LoginType  `json:"type,omitempty"` //Depricated : Needs to cleaned up after removing references
}

// LoginType [Depricated : Needs to cleaned up after removing references]
type LoginType string

const (
	// SelfSigned ...
	SelfSigned LoginType = "Self-Signed"
	// CASigned ...
	CASigned LoginType = "CA-Signed"
)

func LoginTypeToAuthType(authType string) common.AuthenticationType {
	switch authType {
	case string(SelfSigned):
		return common.AuthenticationType_SELFSIGNED
	case string(CASigned):
		return common.AuthenticationType_CASIGNED
	}
	return common.AuthenticationType_SELFSIGNED
}

func AuthTypeToLoginType(authType common.AuthenticationType) LoginType {
	switch authType {
	case common.AuthenticationType_SELFSIGNED:
		return SelfSigned
	case common.AuthenticationType_CASIGNED:
		return CASigned
	}
	return SelfSigned
}

type JwtTokenProvider struct {
	RawData string `json:"rawdata"`
}

func (c JwtTokenProvider) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": c.RawData,
	}, nil
}

func (c JwtTokenProvider) RequireTransportSecurity() bool {
	return true
}

func NewTokenCredentialProvider(token string) JwtTokenProvider {
	return JwtTokenProvider{token}
}

func NewEmptyTokenCredentialProvider() JwtTokenProvider {
	return JwtTokenProvider{}
}

type TransportCredentialsProvider struct {
	serverName            string
	certificate           []tls.Certificate
	rootCAPool            *x509.CertPool
	verifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

func NewEmptyTransportCredential() *TransportCredentialsProvider {
	return &TransportCredentialsProvider{}
}

func NewTransportCredentialFromAuthBase64(serverName string, rootCACertsBase64 string) (*TransportCredentialsProvider, error) {
	caCertPem, err := marshal.FromBase64(rootCACertsBase64)
	if err != nil {
		return nil, fmt.Errorf("could not marshal the server certificate")
	}

	return NewTransportCredentialFromAuthFromPem(serverName, caCertPem)
}

func NewTransportCredentialFromAuthFromPem(serverName string, caCertPem []byte) (*TransportCredentialsProvider, error) {
	certPool := x509.NewCertPool()
	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(caCertPem); !ok {
		return nil, fmt.Errorf("could not append the server certificate")
	}
	return &TransportCredentialsProvider{
		serverName: serverName,
		rootCAPool: certPool,
	}, nil
}

func NewTransportCredentialFromBase64(serverName, clientCertificateBase64, clientKeyBase64 string, rootCACertsBase64 string) (*TransportCredentialsProvider, error) {
	transportCreds, err := NewTransportCredentialFromAuthBase64(serverName, rootCACertsBase64)
	if err != nil {
		return nil, err
	}

	clientPem, err := marshal.FromBase64(clientCertificateBase64)
	if err != nil {
		return nil, err
	}
	keyPem, err := marshal.FromBase64(clientKeyBase64)
	if err != nil {
		return nil, err
	}
	if err = certCheck(clientPem); err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(clientPem, keyPem)
	if err != nil {
		return nil, err
	}

	transportCreds.certificate = []tls.Certificate{tlsCert}

	return transportCreds, nil
}

func NewTransportCredentialFromTlsCerts(serverName string, tlsCerts []tls.Certificate, rootCACertsPem []byte) (*TransportCredentialsProvider, error) {
	transportCreds, err := NewTransportCredentialFromAuthFromPem(serverName, rootCACertsPem)
	if err != nil {
		return nil, err
	}
	transportCreds.certificate = tlsCerts
	return transportCreds, nil
}

func NewTransportCredentialFromAccessFileLocation(serverName, accessFileLocation string) (*TransportCredentialsProvider, error) {
	accessFile := WssdConfig{}
	err := marshal.FromJSONFile(accessFileLocation, &accessFile)
	if err != nil {
		return nil, err
	}
	return NewTransportCredentialFromAccessFile(serverName, accessFile)
}

func NewTransportCredentialFromAccessFile(serverName string, accessFile WssdConfig) (*TransportCredentialsProvider, error) {
	caCertPem, tlscerts, err := AccessFileToTls(accessFile)
	if err != nil {
		return nil, err
	}
	return NewTransportCredentialFromTlsCerts(serverName, []tls.Certificate{tlscerts}, caCertPem)
}

func (transportCredentials *TransportCredentialsProvider) GetTransportCredentials() credentials.TransportCredentials {
	creds := &tls.Config{
		ServerName: transportCredentials.serverName,
	}
	if len(transportCredentials.certificate) > 0 {
		creds.Certificates = transportCredentials.certificate
	}
	if transportCredentials.rootCAPool != nil {
		creds.RootCAs = transportCredentials.rootCAPool
	}
	if transportCredentials.verifyPeerCertificate != nil {
		creds.VerifyPeerCertificate = transportCredentials.verifyPeerCertificate
	}
	return credentials.NewTLS(creds)
}

// BearerAuthorizer implements the bearer authorization
type BearerAuthorizer struct {
	tokenProvider        JwtTokenProvider
	transportCredentials credentials.TransportCredentials
}

func (ba *BearerAuthorizer) WithRPCAuthorization() credentials.PerRPCCredentials {
	return ba.tokenProvider
}

func (ba *BearerAuthorizer) WithTransportAuthorization() credentials.TransportCredentials {
	return ba.transportCredentials
}

func NewEmptyBearerAuthorizer() *BearerAuthorizer {
	return &BearerAuthorizer{
		tokenProvider:        NewEmptyTokenCredentialProvider(),
		transportCredentials: NewEmptyBearerAuthorizer().transportCredentials,
	}
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
	settings := GetSettingsFromEnvironment(serverName)
	err := RenewCertificates(settings.GetManagedIdentityConfig().ServerName, settings.GetManagedIdentityConfig().WssdConfigPath)
	if err != nil {
		return nil, err
	}
	return settings.GetAuthorizer()
}

func NewAuthorizerFromEnvironmentByName(serverName, subfolder, filename string) (Authorizer, error) {
	settings, err := GetSettingsFromEnvironmentByName(serverName, subfolder, filename)
	if err != nil {
		return nil, err
	}
	err = RenewCertificates(settings.GetManagedIdentityConfig().ServerName, settings.GetManagedIdentityConfig().WssdConfigPath)
	if err != nil {
		return nil, err
	}
	return settings.GetAuthorizer()
}

func NewAuthorizerFromInput(tlsCert tls.Certificate, serverCertificate []byte, server string) (Authorizer, error) {
	transportCreds := TransportCredentialsFromNode(tlsCert, serverCertificate, server)
	return NewBearerAuthorizer(NewEmptyTokenCredentialProvider(), transportCreds), nil
}

func NewAuthorizerForAuth(tokenString string, certificate string, server string) (Authorizer, error) {
	credentials, err := NewTransportCredentialFromAuthBase64(server, certificate)
	if err != nil {
		return NewEmptyBearerAuthorizer(), err
	}
	return NewBearerAuthorizer(NewTokenCredentialProvider(tokenString), credentials.GetTransportCredentials()), nil
}

// GetSettingsFromEnvironment Read settings from WssdConfigLocation
func GetSettingsFromEnvironment(serverName string) (s EnvironmentSettings) {
	s = EnvironmentSettings{
		Values: map[string]string{},
	}
	s.Values[ClientTokenPath] = getClientTokenLocation()
	s.Values[WssdConfigPath] = GetWssdConfigLocation()

	s.Values[ServerName] = serverName

	return
}

// GetSettingsFromEnvironmentByName Read settings from GetWssdConfigLocationName
func GetSettingsFromEnvironmentByName(serverName, subfolder, filename string) (s EnvironmentSettings, err error) {
	s = EnvironmentSettings{
		Values: map[string]string{},
	}
	s.Values[ClientTokenPath] = getClientTokenLocation()
	s.Values[WssdConfigPath] = GetMocConfigLocationName(subfolder, filename)
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

	jwtCreds, err := TokenProviderFromFile(mc.ClientTokenPath)
	if err != nil {
		return nil, err
	}
	transportCreds := TransportCredentialsFromFile(mc.WssdConfigPath, mc.ServerName)

	return NewBearerAuthorizer(jwtCreds, transportCreds), nil
}

func TokenProviderFromFile(tokenLocation string) (JwtTokenProvider, error) {
	if tokenLocation == "" {
		return NewEmptyTokenCredentialProvider(), nil
	}
	loginconfig := LoginConfig{}
	err := config.LoadYAMLFile(tokenLocation, &loginconfig)
	if err != nil {
		// if File does not exist we return no error. This to prevent any breaking changes
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		return NewEmptyTokenCredentialProvider(), err
	}
	return NewTokenCredentialProvider(loginconfig.Token), nil
}

func TransportCredentialsFromFile(wssdConfigLocation string, server string) credentials.TransportCredentials {
	credentials, err := NewTransportCredentialFromAccessFileLocation(server, wssdConfigLocation)
	if err != nil {
		return NewEmptyTransportCredential().GetTransportCredentials()
	}
	return credentials.GetTransportCredentials()
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

	credential, err := NewTransportCredentialFromTlsCerts(server, []tls.Certificate{tlsCert}, serverCertificate)
	if err != nil {
		return NewEmptyTransportCredential().GetTransportCredentials()
	}
	return credential.GetTransportCredentials()

}

func SaveToken(tokenStr string) error {
	return ioutil.WriteFile(
		getClientTokenLocation(),
		[]byte(tokenStr),
		0644)
}

// PrintAccessFile stores wssdConfig in WssdConfigLocation
func PrintAccessFile(accessFile WssdConfig) error {
	return marshal.ToJSONFile(accessFile, GetWssdConfigLocation())
}

// PrintAccessFileByName stores wssdConfig in GetWssdConfigLocationName
func PrintAccessFileByName(accessFile WssdConfig, subfolder, filename string) error {
	return marshal.ToJSONFile(accessFile, GetMocConfigLocationName(subfolder, filename))
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

	if err = certCheck(clientPem); err != nil {
		return []byte{}, tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(clientPem, keyPem)
	if err != nil {
		return []byte{}, tls.Certificate{}, err
	}

	return serverPem, tlsCert, nil
}
