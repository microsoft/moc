// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package auth

import (
	context "context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/microsoft/moc/pkg/certs"
	"github.com/microsoft/moc/pkg/marshal"
	wssdnet "github.com/microsoft/moc/pkg/net"
	"github.com/microsoft/moc/rpc/common"
	"github.com/pkg/errors"
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

// LoginType
type LoginType string

const (
	// SelfSigned ...
	SelfSigned LoginType = "Self-Signed"
	// CASigned ...
	CASigned LoginType = "CA-Signed"
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
	Name          string    `json:"name,omitempty"`
	Token         string    `json:"token,omitempty"`
	Certificate   string    `json:"certificate,omitempty"`
	ClientType    string    `json:"clienttype,omitempty"`
	CloudFqdn     string    `json:"cloudfqdn,omitempty"`
	CloudPort     int32     `json:"cloudport,omitempty"`
	CloudAuthPort int32     `json:"cloudauthport,omitempty"`
	CACertHash    string    `json:"cacerthash,omitempty"`
	Location      string    `json:"location,omitempty"`
	Type          LoginType `json:"type,omitempty"`
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

func NewAuthorizerFromEnvironmentByName(serverName, subfolder, filename string) (Authorizer, error) {
	settings, err := GetSettingsFromEnvironmentByName(serverName, subfolder, filename)
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

func NewAuthorizerForAuthFromCACertHash(tokenString string, cacerthash string, server string) (Authorizer, error) {
	pkv := NewPublicKeyVerifier()
	err := pkv.Allow(cacerthash)
	if err != nil {
		return NewBearerAuthorizer(JwtTokenProvider{}, credentials.NewTLS(nil)), fmt.Errorf("could not marshal the server certificate")
	}

	transportCreds := credentials.NewTLS(&tls.Config{
		ServerName:            server,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pkv.VerifyPeerCertificate,
		RootCAs:               x509.NewCertPool(),
	})

	return NewBearerAuthorizer(JwtTokenProvider{tokenString}, transportCreds), nil
}

// GetSettingsFromEnvironment Read settings from WssdConfigLocation
func GetSettingsFromEnvironment(serverName string) (s EnvironmentSettings, err error) {
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

func getExecutableName() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(filepath.Base(execPath), filepath.Ext(execPath)), nil
}

// GetWssdConfigLocation gets the path for access file from environment
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
		if execName, err := getExecutableName(); err == nil {
			defaultPath = filepath.Join(defaultPath, execName)
		}
		os.MkdirAll(defaultPath, os.ModePerm)
		wssdConfigPath = filepath.Join(defaultPath, AccessFileDefaultName)
		os.Setenv(WssdConfigPath, wssdConfigPath)
	}
	return wssdConfigPath
}

// GetWssdConfigLocationName gets the path for access filename from environment + subfolder with file name fileName
func GetMocConfigLocationName(subfolder, filename string) string {
	wssdConfigPath := os.Getenv(WssdConfigPath)

	file := AccessFileDefaultName
	if filename != "" {
		file = filename
	}
	wd, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	if wssdConfigPath == "" || !strings.HasSuffix(wssdConfigPath, filepath.Join(wd, subfolder, file)) {
		// Create the default config path and set the
		// env variable
		defaultPath := filepath.Join(wd, DefaultWSSDFolder, subfolder)
		os.MkdirAll(defaultPath, os.ModePerm)
		wssdConfigPath = filepath.Join(defaultPath, file)
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

// GenerateClientKey generates key and self-signed cert if the file does not exist in WssdConfigLocation
// If the file exists the values from the fie is returned
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

func GenerateClientCsr(loginconfig LoginConfig) (string, WssdConfig, error) {
	certBytes, err := marshal.FromBase64(loginconfig.Certificate)
	if err != nil {
		return "", WssdConfig{}, err
	}
	accessFile, err := readAccessFile(GetWssdConfigLocation())
	cloudAgentIpAddress, err := wssdnet.GetIPAddress()
	if err != nil {
		return "", WssdConfig{}, err
	}

	localHostName, err := os.Hostname()
	if err != nil {
		return "", WssdConfig{}, err
	}

	cloudAgentIPAddress := wssdnet.StringToNetIPAddress(cloudAgentIpAddress)
	ipAddresses := []net.IP{wssdnet.StringToNetIPAddress(wssdnet.LOOPBACK_ADDRESS), cloudAgentIPAddress}
	dnsNames := []string{"localhost", localHostName}

	conf := &certs.Config{
		CommonName: loginconfig.Name,
		AltNames: certs.AltNames{
			DNSNames: dnsNames,
			IPs:      ipAddresses,
		},
	}
	x509Csr, keyClient, err := certs.GenerateCertificateRequest(conf, nil)
	if err != nil {
		return "", WssdConfig{}, err
	}

	accessFile = WssdConfig{
		CloudCertificate:  "",
		ClientCertificate: "",
		ClientKey:         marshal.ToBase64(string(keyClient)),
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
	return string(x509Csr), accessFile, nil
}

// GenerateClientKeyWithName generates key and self-signed cert if the file does not exist in GetWssdConfigLocationName
// If the file exists the values from the fie is returned
func GenerateClientKeyWithName(loginconfig LoginConfig, subfolder, filename string) (string, WssdConfig, error) {
	certBytes, err := marshal.FromBase64(loginconfig.Certificate)
	if err != nil {
		return "", WssdConfig{}, err
	}
	accessFile, err := readAccessFile(GetMocConfigLocationName(subfolder, filename))
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

func GetServerCertificateFromHash(server, caCertHash string) (string, error) {
	sp := strings.Split(server, ":")
	if len(sp) != 2 {
		return "", errors.Errorf("server must be the hostname + ':' + port, was %s", server)
	}

	if _, err := strconv.Atoi(sp[1]); err != nil {
		return "", errors.Errorf("server must have integer after ':', had %s", sp[1])
	}

	nconn, err := net.Dial("tcp", server)
	if err != nil {
		return "", errors.Wrapf(err, "problem dialing %s", server)
	}

	pkv := NewPublicKeyVerifier()
	err = pkv.Allow(caCertHash)
	if err != nil {
		return "", errors.Wrapf(err, "problem dialing %s", server)
	}

	config := &tls.Config{
		ServerName:            server,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pkv.VerifyPeerCertificate,
		RootCAs:               x509.NewCertPool(),
	}

	tconn := tls.Client(nconn, config)
	if err := tconn.Handshake(); err != nil {
		return "", errors.Wrap(err, "problem with TLS handshake")
	}

	if len(tconn.ConnectionState().PeerCertificates) == 0 {
		return "", errors.Errorf("unable to retieve certificates from %s ", server)
	}

	certBytesClient := certs.EncodeCertPEM(tconn.ConnectionState().PeerCertificates[0])

	return marshal.ToBase64(string(certBytesClient)), nil
}

// PrintAccessFile stores wssdConfig in WssdConfigLocation
func PrintAccessFile(accessFile WssdConfig) error {
	return marshal.ToJSONFile(accessFile, GetWssdConfigLocation())
}

// PrintAccessFileByName stores wssdConfig in GetWssdConfigLocationName
func PrintAccessFileByName(accessFile WssdConfig, subfolder, filename string) error {
	fmt.Println("Rgha")
	return marshal.ToJSONFile(accessFile, GetMocConfigLocationName(subfolder, filename))
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
