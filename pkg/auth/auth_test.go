// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package auth

import (
	context "context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	gomock "github.com/golang/mock/gomock"
	mock "github.com/microsoft/moc/pkg/auth/mock"
	"github.com/microsoft/moc/pkg/certs"
	"github.com/microsoft/moc/pkg/errors"

	"github.com/microsoft/moc/pkg/marshal"
	"github.com/microsoft/moc/rpc/testagent"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func IsTransportUnavailable(err error) bool {
	if e, ok := status.FromError(err); ok && e.Code() == codes.Unavailable {
		return true
	}
	return false
}

type JwtAuthorizer struct {
	jwtPublicKey *rsa.PublicKey
}

func validateToken(tokenString string, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Wrapf(errors.NotSupported, "Unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, errors.Wrapf(errors.InvalidToken, "Valid Token Required %v", err)
	}
	if !parsedToken.Valid {
		return nil, errors.Wrapf(errors.InvalidToken, "Valid Token Required")
	}

	return parsedToken, nil
}

// ValidateLoginTokenFromContext obtains the token from the context of the call
func (ja *JwtAuthorizer) ValidateLoginTokenFromContext(context context.Context) (*jwt.Token, error) {
	var token *jwt.Token
	var err error
	md, ok := metadata.FromIncomingContext(context)
	if !ok {
		return nil, fmt.Errorf("Metadata is not provided")
	}

	jwtToken, ok := md["authorization"]
	if !ok {
		return nil, fmt.Errorf("authorization token is not provided")
	}
	token, err = validateToken(jwtToken[0], ja.jwtPublicKey)
	if err != nil && !errors.IsInvalidToken(err) {
		return nil, err
	}
	if err == nil {
		return token, nil
	}

	return nil, errors.Wrapf(errors.InvalidToken, "Valid Token Required")
}

type JwtSigner struct {
	jwtPrivateKey *rsa.PrivateKey
}

type claims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

func NewJwtSigner(privateKeyByte []byte) (*JwtSigner, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyByte)
	if err != nil {
		return nil, fmt.Errorf("Error parsing private key: %v", err)
	}

	return &JwtSigner{privateKey}, nil
}

// IssueJWT issues a JWT from the name and guid and expiry duration in seconds
func (js *JwtSigner) IssueJWTWithValidityInSeconds(name string, guid string, expiryInSeconds int64) (string, error) {
	if expiryInSeconds <= 0 {
		return "", fmt.Errorf("expiry cannot be negative or zero")
	}

	cl := &claims{
		Name: name,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * time.Duration(expiryInSeconds)).Unix(),
			Id:        guid,
			IssuedAt:  time.Now().Unix(),
			Issuer:    "Test",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, cl)
	return token.SignedString(js.jwtPrivateKey)
}

func NewJwtAuthorizerFromKey(key crypto.PublicKey) (*JwtAuthorizer, error) {
	authorizer := JwtAuthorizer{}
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return &JwtAuthorizer{}, fmt.Errorf("Error parsing public key")
	}
	authorizer.jwtPublicKey = publicKey
	return &authorizer, nil
}

type TestAuthServer struct {
	JwtAuth *JwtAuthorizer
}

func (s *TestAuthServer) PingHolla(ctx context.Context, in *testagent.Holla) (*testagent.Holla, error) {
	_, err := s.JwtAuth.ValidateLoginTokenFromContext(ctx)
	if err != nil {
		return &testagent.Holla{}, err
	}
	return &testagent.Holla{Name: "Holla From the Server!" + in.Name}, nil
}

type TestTlsServer struct {
}

func (s *TestTlsServer) PingHello(ctx context.Context, in *testagent.Hello) (*testagent.Hello, error) {
	return &testagent.Hello{Name: "Hello From the Server!" + in.Name}, nil
}

func getClientCert(t *testing.T) (tls.Certificate, []byte, []byte) {
	cert, key, err := certs.GenerateClientCertificate("test")
	certPem := certs.EncodeCertPEM(cert)
	keyPem := certs.EncodePrivateKeyPEM(key)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to get tls cert", err)
	return tlsCert, certPem, keyPem
}

func startHelloServer(grpcServer *grpc.Server, address string) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	tlsServer := TestTlsServer{}
	testagent.RegisterHelloAgentServer(grpcServer, &tlsServer)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

func startHollaServer(grpcServer *grpc.Server, jwtAuth *JwtAuthorizer, address string) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	tlsServer := TestAuthServer{JwtAuth: jwtAuth}
	testagent.RegisterHollaAgentServer(grpcServer, &tlsServer)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

func getAuthCreds(t *testing.T, tlsCert tls.Certificate) credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		Certificates:             []tls.Certificate{tlsCert},
	})
}

func getTlsCreds(t *testing.T, tlsCert tls.Certificate, certPem []byte) credentials.TransportCredentials {

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(certPem)
	assert.True(t, ok, "Failed setting up cert pool")

	return credentials.NewTLS(&tls.Config{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequestClientCert,
		Certificates:             []tls.Certificate{tlsCert},
		ClientCAs:                certPool,
	})
}

// For poptoken, the client does not validate the server's identity during the TLS handshake as communication goes
// through a secure channel via Azure Relay. Hence the server just need to pass in any TLS cert.
func getDisableTlsCreds(t *testing.T, tlsCert tls.Certificate, certPem []byte) credentials.TransportCredentials {

	return credentials.NewServerTLSFromCert(&tlsCert)
}

func getGrpcServer(t *testing.T, creds credentials.TransportCredentials) *grpc.Server {
	var opts []grpc.ServerOption
	opts = append(opts, grpc.Creds(creds))
	grpcServer := grpc.NewServer(opts...)
	return grpcServer
}

func getAuthServer(t *testing.T) (*grpc.Server, *JwtAuthorizer, []byte, []byte) {
	tlsCert, certPem, keyPem := getClientCert(t)
	creds := getAuthCreds(t, tlsCert)
	grpcServer := getGrpcServer(t, creds)
	key, err := certs.DecodePrivateKeyPEM(keyPem)
	assert.NoErrorf(t, err, "Failed to decode PrivateKey", err)
	jwtAuth, err := NewJwtAuthorizerFromKey(key.Public())
	assert.NoErrorf(t, err, "Failed to Jwt Authorizer", err)
	return grpcServer, jwtAuth, certPem, keyPem
}

func generateToken(t *testing.T, privateKeyPem []byte) string {
	jwtSigner, err := NewJwtSigner(privateKeyPem)
	assert.NoErrorf(t, err, "Failed to create jwtSigner", err)
	token, err := jwtSigner.IssueJWTWithValidityInSeconds("test", "12345", 60)
	assert.NoErrorf(t, err, "Failed to create token", err)
	return token

}

func makeAuthCall(t *testing.T, address string, tokenAuth credentials.PerRPCCredentials, tlsProvider credentials.TransportCredentials) (*testagent.Holla, error) {
	conn, err := grpc.Dial(address, grpc.WithPerRPCCredentials(tokenAuth), grpc.WithTransportCredentials(tlsProvider))
	assert.NoErrorf(t, err, "Failed to dial", err)
	defer conn.Close()
	c := testagent.NewHollaAgentClient(conn)
	return c.PingHolla(context.Background(), &testagent.Holla{Name: "AuthServer"})
}

func makeTlsCall(t *testing.T, address string, provider credentials.TransportCredentials) (*testagent.Hello, error) {
	var conn *grpc.ClientConn
	var err error
	if provider != nil {
		conn, err = grpc.Dial(address, grpc.WithTransportCredentials(provider))
	} else {
		conn, err = grpc.Dial(address, grpc.WithInsecure())
	}
	assert.NoErrorf(t, err, "Failed to dial", err)
	defer conn.Close()
	c := testagent.NewHelloAgentClient(conn)
	return c.PingHello(context.Background(), &testagent.Hello{Name: "TLSServer"})
}
func Test_InvalidTokenAuthServer(t *testing.T) {
	server := "localhost"
	port := "9001"
	address := server + ":" + port
	grpcServer, jwtAuth, certPem, _ := getAuthServer(t)
	go startHollaServer(grpcServer, jwtAuth, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privatekeyPem := certs.EncodePrivateKeyPEM(privateKey)
	token := generateToken(t, privatekeyPem)
	tokenAuth := NewTokenCredentialProvider(token)
	providerAuth, err := NewTransportCredentialFromAuthFromPem(server, certPem)
	assert.NoErrorf(t, err, "Failed to create tls credentials", err)
	_, err = makeAuthCall(t, address, tokenAuth, providerAuth.GetTransportCredentials())
	assert.Equal(t, err.Error(), "rpc error: code = Unknown desc = Valid Token Required: InvalidToken", "Error Expected but missing ", err.Error())
}

func Test_AuthServer(t *testing.T) {
	server := "localhost"
	port := "9001"
	address := server + ":" + port
	grpcServer, jwtAuth, certPem, keyPem := getAuthServer(t)
	go startHollaServer(grpcServer, jwtAuth, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))

	token := generateToken(t, keyPem)
	tokenAuth := NewTokenCredentialProvider(token)
	providerAuth, err := NewTransportCredentialFromAuthFromPem(server, certPem)
	assert.NoErrorf(t, err, "Failed to create tls credentials", err)
	response, err := makeAuthCall(t, address, tokenAuth, providerAuth.GetTransportCredentials())
	assert.NoErrorf(t, err, "Failed to make auth call", err)
	assert.Equal(t, response.Name, "Holla From the Server!AuthServer")
}

func Test_InsecureServer(t *testing.T) {
	server := "localhost"
	port := "9005"
	address := server + ":" + port
	tlsCert, certPem, _ := getClientCert(t)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServer := getGrpcServer(t, creds)
	go startHelloServer(grpcServer, address)
	defer grpcServer.Stop()
	time.Sleep((time.Second * 3))
	_, err := makeTlsCall(t, address, nil)
	assert.True(t, IsTransportUnavailable(err))
}

func Test_TLSInvalidCertificate(t *testing.T) {
	server := "localhost"
	port := "9005"
	address := server + ":" + port
	tlsCert, certPem, _ := getClientCert(t)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServer := getGrpcServer(t, creds)
	go startHelloServer(grpcServer, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))
	tlsCert1, certPem1, _ := getClientCert(t)
	provider, err := NewTransportCredentialFromTlsCerts(server, []tls.Certificate{tlsCert1}, certPem1)
	assert.NoErrorf(t, err, "Failed to create TLS Credentials", err)
	fmt.Println("Invalid certificate")
	_, err = makeTlsCall(t, address, provider.GetTransportCredentials())
	assert.True(t, strings.Contains(err.Error(), "certificate signed by unknown authority"), err.Error())
}

func Test_TLSServer(t *testing.T) {
	server := "localhost"
	port := "9005"
	address := server + ":" + port
	tlsCert, certPem, _ := getClientCert(t)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServer := getGrpcServer(t, creds)
	go startHelloServer(grpcServer, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))
	provider, err := NewTransportCredentialFromTlsCerts(server, []tls.Certificate{tlsCert}, certPem)
	assert.NoErrorf(t, err, "Failed to create TLS Credentials", err)

	response, err := makeTlsCall(t, address, provider.GetTransportCredentials())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, response.Name, "Hello From the Server!TLSServer")
}

func Test_TLSAuthServer(t *testing.T) {
	server := "localhost"
	tlsPort := "9005"
	authPort := "9001"
	tlsAddress := server + ":" + tlsPort
	authAddress := server + ":" + authPort
	grpcServerAuth, jwtAuth, certPem, keyPem := getAuthServer(t)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to x509keypair", err)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServertls := getGrpcServer(t, creds)
	go startHelloServer(grpcServertls, tlsAddress)
	defer grpcServertls.Stop()

	go startHollaServer(grpcServerAuth, jwtAuth, authAddress)
	defer grpcServerAuth.Stop()

	time.Sleep((time.Second * 3))
	provider, err := NewTransportCredentialFromTlsCerts(server, []tls.Certificate{tlsCert}, certPem)
	assert.NoErrorf(t, err, "Failed to create TLS Credentials", err)

	responsetls, err := makeTlsCall(t, tlsAddress, provider.GetTransportCredentials())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, responsetls.Name, "Hello From the Server!TLSServer")

	token := generateToken(t, keyPem)
	tokenAuth := NewTokenCredentialProvider(token)
	providerAuth, err := NewTransportCredentialFromAuthFromPem(server, certPem)
	assert.NoErrorf(t, err, "Failed to create tls credentials", err)
	responseAuth, err := makeAuthCall(t, authAddress, tokenAuth, providerAuth.GetTransportCredentials())
	assert.NoErrorf(t, err, "Failed to make auth call", err)
	assert.Equal(t, responseAuth.Name, "Holla From the Server!AuthServer")
}

func Test_AuthServerTokenProviderFromFile(t *testing.T) {
	server := "localhost"
	port := "9001"
	address := server + ":" + port
	grpcServer, jwtAuth, certPem, keyPem := getAuthServer(t)
	go startHollaServer(grpcServer, jwtAuth, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))

	token := generateToken(t, keyPem)
	loginconfig := LoginConfig{}
	loginconfig.Token = token
	dirPath := t.TempDir()
	loginConfigPath := filepath.Join(dirPath, "loginconfig.yaml")
	err := marshal.ToYAMLFile(loginconfig, loginConfigPath)
	assert.NoErrorf(t, err, "Failed to write yaml", err)
	defer os.Remove(loginConfigPath)
	tokenAuth, err := TokenProviderFromFile(loginConfigPath)
	assert.NoErrorf(t, err, "Failed to get token provider from File", err)
	providerAuth, err := NewTransportCredentialFromAuthFromPem(server, certPem)
	assert.NoErrorf(t, err, "Failed to create tls credentials", err)
	response, err := makeAuthCall(t, address, tokenAuth, providerAuth.GetTransportCredentials())
	assert.NoErrorf(t, err, "Failed to make auth call", err)
	assert.Equal(t, response.Name, "Holla From the Server!AuthServer")
}

func Test_AuthServerNewAuthorizerForAuth(t *testing.T) {
	server := "localhost"
	port := "9001"
	address := server + ":" + port
	grpcServer, jwtAuth, certPem, keyPem := getAuthServer(t)
	go startHollaServer(grpcServer, jwtAuth, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))
	certBAse64 := marshal.ToBase64(string(certPem))
	token := generateToken(t, keyPem)
	authorizer, err := NewAuthorizerForAuth(token, certBAse64, server)
	assert.NoErrorf(t, err, "Failed to get token provider from File", err)
	response, err := makeAuthCall(t, address, authorizer.WithRPCAuthorization(), authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make auth call", err)
	assert.Equal(t, response.Name, "Holla From the Server!AuthServer")
}

func Test_TransportCredentialsFromNode(t *testing.T) {
	server := "localhost"
	port := "9005"
	address := server + ":" + port
	tlsCert, certPem, _ := getClientCert(t)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServer := getGrpcServer(t, creds)
	go startHelloServer(grpcServer, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))
	provider := TransportCredentialsFromNode(tlsCert, certPem, server)
	response, err := makeTlsCall(t, address, provider)
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, response.Name, "Hello From the Server!TLSServer")
}

func Test_TransportCredentialsNewAuthorizerFromInput(t *testing.T) {
	server := "localhost"
	port := "9005"
	address := server + ":" + port
	tlsCert, certPem, _ := getClientCert(t)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServer := getGrpcServer(t, creds)
	go startHelloServer(grpcServer, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))
	provider, err := NewAuthorizerFromInput(tlsCert, certPem, server)
	assert.NoErrorf(t, err, "Failed to create NewAuthorizerFromInput", err)
	response, err := makeTlsCall(t, address, provider.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, response.Name, "Hello From the Server!TLSServer")
}

func Test_TransportCredentialsFromFile(t *testing.T) {
	server := "localhost"
	port := "9005"
	address := server + ":" + port

	tlsCert, certPem, keyPem := getClientCert(t)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServer := getGrpcServer(t, creds)
	go startHelloServer(grpcServer, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))
	accessFile := WssdConfig{}
	accessFile.CloudCertificate = marshal.ToBase64(string(certPem))
	accessFile.ClientKey = marshal.ToBase64(string(keyPem))
	accessFile.ClientCertificate = marshal.ToBase64(string(certPem))
	dirPath := t.TempDir()
	wssdConfigPath := filepath.Join(dirPath, "wssdconfig")

	err := marshal.ToJSONFile(&accessFile, wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to marshall json file", err)
	defer os.Remove(wssdConfigPath)
	provider := TransportCredentialsFromFile(wssdConfigPath, server)
	response, err := makeTlsCall(t, address, provider)
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, response.Name, "Hello From the Server!TLSServer")
}

func Test_TLSAuthServerEnvironmentSetting(t *testing.T) {
	server := "localhost"
	tlsPort := "9005"
	authPort := "9001"
	tlsAddress := server + ":" + tlsPort
	authAddress := server + ":" + authPort
	grpcServerAuth, jwtAuth, certPem, keyPem := getAuthServer(t)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to x509keypair", err)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServertls := getGrpcServer(t, creds)
	go startHelloServer(grpcServertls, tlsAddress)
	defer grpcServertls.Stop()

	go startHollaServer(grpcServerAuth, jwtAuth, authAddress)
	defer grpcServerAuth.Stop()

	time.Sleep((time.Second * 3))

	token := generateToken(t, keyPem)
	loginconfig := LoginConfig{}
	loginconfig.Token = token
	dirPath := t.TempDir()
	loginConfigPath := filepath.Join(dirPath, "loginconfig.yaml")
	err = marshal.ToYAMLFile(loginconfig, loginConfigPath)
	assert.NoErrorf(t, err, "Failed to write yaml", err)
	defer os.Remove(loginConfigPath)

	accessFile := WssdConfig{}
	accessFile.CloudCertificate = marshal.ToBase64(string(certPem))
	accessFile.ClientKey = marshal.ToBase64(string(keyPem))
	accessFile.ClientCertificate = marshal.ToBase64(string(certPem))
	wssdConfigPath := filepath.Join(dirPath, "wssdconfig")
	err = marshal.ToJSONFile(&accessFile, wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to marshall json file", err)
	defer os.Remove(wssdConfigPath)

	settings := EnvironmentSettings{
		Values: map[string]string{
			ClientTokenPath: loginConfigPath,
			WssdConfigPath:  wssdConfigPath,
			ServerName:      server,
		},
	}
	authorizer, err := settings.GetAuthorizer()
	assert.NoErrorf(t, err, "Failed to create authorizer", err)

	responseAuth, err := makeAuthCall(t, authAddress, authorizer.WithRPCAuthorization(), authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make auth call", err)
	assert.Equal(t, responseAuth.Name, "Holla From the Server!AuthServer")

	responsetls, err := makeTlsCall(t, tlsAddress, authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, responsetls.Name, "Hello From the Server!TLSServer")

}

func Test_TLSAuthServerEnvironmentSettingTokenFileNotExist(t *testing.T) {
	server := "localhost"
	tlsPort := "9005"
	authPort := "9001"
	tlsAddress := server + ":" + tlsPort
	authAddress := server + ":" + authPort
	grpcServerAuth, jwtAuth, certPem, keyPem := getAuthServer(t)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to x509keypair", err)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServertls := getGrpcServer(t, creds)
	go startHelloServer(grpcServertls, tlsAddress)
	defer grpcServertls.Stop()

	go startHollaServer(grpcServerAuth, jwtAuth, authAddress)
	defer grpcServerAuth.Stop()

	time.Sleep((time.Second * 3))

	dirPath := t.TempDir()
	loginConfigPath := filepath.Join(dirPath, "loginconfig.yaml")

	accessFile := WssdConfig{}
	accessFile.CloudCertificate = marshal.ToBase64(string(certPem))
	accessFile.ClientKey = marshal.ToBase64(string(keyPem))
	accessFile.ClientCertificate = marshal.ToBase64(string(certPem))
	wssdConfigPath := filepath.Join(dirPath, "wssdconfig")
	err = marshal.ToJSONFile(&accessFile, wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to marshall json file", err)
	defer os.Remove(wssdConfigPath)

	settings := EnvironmentSettings{
		Values: map[string]string{
			ClientTokenPath: loginConfigPath,
			WssdConfigPath:  wssdConfigPath,
			ServerName:      server,
		},
	}
	authorizer, err := settings.GetAuthorizer()
	assert.NoErrorf(t, err, "Failed to create authorizer", err)

	_, err = makeAuthCall(t, authAddress, authorizer.WithRPCAuthorization(), authorizer.WithTransportAuthorization())
	assert.Equal(t, err.Error(), "rpc error: code = Unknown desc = Valid Token Required: InvalidToken", "Error Expected but missing ", err.Error())

	responsetls, err := makeTlsCall(t, tlsAddress, authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, responsetls.Name, "Hello From the Server!TLSServer")

}

func Test_TLSAuthServerEnvironmentSettingWithEmptyTokenFile(t *testing.T) {
	server := "localhost"
	tlsPort := "9005"
	authPort := "9001"
	tlsAddress := server + ":" + tlsPort
	authAddress := server + ":" + authPort
	grpcServerAuth, jwtAuth, certPem, keyPem := getAuthServer(t)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to x509keypair", err)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServertls := getGrpcServer(t, creds)
	go startHelloServer(grpcServertls, tlsAddress)
	defer grpcServertls.Stop()

	go startHollaServer(grpcServerAuth, jwtAuth, authAddress)
	defer grpcServerAuth.Stop()

	time.Sleep((time.Second * 3))

	dirPath := t.TempDir()
	accessFile := WssdConfig{}
	accessFile.CloudCertificate = marshal.ToBase64(string(certPem))
	accessFile.ClientKey = marshal.ToBase64(string(keyPem))
	accessFile.ClientCertificate = marshal.ToBase64(string(certPem))
	wssdConfigPath := filepath.Join(dirPath, "wssdconfig")
	err = marshal.ToJSONFile(&accessFile, wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to marshall json file", err)
	defer os.Remove(wssdConfigPath)

	settings := EnvironmentSettings{
		Values: map[string]string{
			WssdConfigPath: wssdConfigPath,
			ServerName:     server,
		},
	}
	authorizer, err := settings.GetAuthorizer()
	assert.NoErrorf(t, err, "Failed to create authorizer", err)

	_, err = makeAuthCall(t, authAddress, authorizer.WithRPCAuthorization(), authorizer.WithTransportAuthorization())
	assert.Equal(t, err.Error(), "rpc error: code = Unknown desc = Valid Token Required: InvalidToken", "Error Expected but missing ", err.Error())

	responsetls, err := makeTlsCall(t, tlsAddress, authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, responsetls.Name, "Hello From the Server!TLSServer")

}

func Test_TLSAuthServerFromEnvironment(t *testing.T) {
	server := "localhost"
	tlsPort := "9005"
	authPort := "9001"
	tlsAddress := server + ":" + tlsPort
	authAddress := server + ":" + authPort
	grpcServerAuth, jwtAuth, certPem, keyPem := getAuthServer(t)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to x509keypair", err)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServertls := getGrpcServer(t, creds)
	go startHelloServer(grpcServertls, tlsAddress)
	defer grpcServertls.Stop()

	go startHollaServer(grpcServerAuth, jwtAuth, authAddress)
	defer grpcServerAuth.Stop()

	time.Sleep((time.Second * 3))

	token := generateToken(t, keyPem)
	loginconfig := LoginConfig{}
	loginconfig.Token = token
	dirPath := t.TempDir()
	loginConfigPath := filepath.Join(dirPath, "loginconfig.yaml")
	err = marshal.ToYAMLFile(loginconfig, loginConfigPath)
	assert.NoErrorf(t, err, "Failed to write yaml", err)
	defer os.Remove(loginConfigPath)

	accessFile := WssdConfig{}
	accessFile.CloudCertificate = marshal.ToBase64(string(certPem))
	accessFile.ClientKey = marshal.ToBase64(string(keyPem))
	accessFile.ClientCertificate = marshal.ToBase64(string(certPem))
	wssdConfigPath := filepath.Join(dirPath, "wssdconfig")
	err = marshal.ToJSONFile(&accessFile, wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to marshall json file", err)
	defer os.Remove(wssdConfigPath)

	err = SetCertificateDirPath("")
	assert.NoErrorf(t, err, "Failed to set env", err)
	err = SetCertificateFilePath(wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to set env", err)
	defer SetCertificateFilePath("")
	err = SetLoginTokenPath(loginConfigPath)
	assert.NoErrorf(t, err, "Failed to set env", err)
	defer SetLoginTokenPath("")

	authorizer, err := GetSettingsFromEnvironment(server).GetAuthorizer()
	assert.NoErrorf(t, err, "Failed to create authorizer", err)

	responseAuth, err := makeAuthCall(t, authAddress, authorizer.WithRPCAuthorization(), authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make auth call", err)
	assert.Equal(t, responseAuth.Name, "Holla From the Server!AuthServer")

	responsetls, err := makeTlsCall(t, tlsAddress, authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, responsetls.Name, "Hello From the Server!TLSServer")
}

func Test_TLSAuthServerFromEnvironmentTokenFileNotExist(t *testing.T) {
	server := "localhost"
	tlsPort := "9005"
	authPort := "9001"
	tlsAddress := server + ":" + tlsPort
	authAddress := server + ":" + authPort
	grpcServerAuth, jwtAuth, certPem, keyPem := getAuthServer(t)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to x509keypair", err)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServertls := getGrpcServer(t, creds)
	go startHelloServer(grpcServertls, tlsAddress)
	defer grpcServertls.Stop()

	go startHollaServer(grpcServerAuth, jwtAuth, authAddress)
	defer grpcServerAuth.Stop()

	time.Sleep((time.Second * 3))

	dirPath := t.TempDir()
	loginConfigPath := filepath.Join(dirPath, "loginconfig.yaml")
	defer os.Remove(loginConfigPath)

	accessFile := WssdConfig{}
	accessFile.CloudCertificate = marshal.ToBase64(string(certPem))
	accessFile.ClientKey = marshal.ToBase64(string(keyPem))
	accessFile.ClientCertificate = marshal.ToBase64(string(certPem))
	wssdConfigPath := filepath.Join(dirPath, "wssdconfig")
	err = marshal.ToJSONFile(&accessFile, wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to marshall json file", err)
	defer os.Remove(wssdConfigPath)

	err = SetCertificateDirPath("")
	assert.NoErrorf(t, err, "Failed to set env", err)
	err = SetCertificateFilePath(wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to set env", err)
	defer SetCertificateFilePath("")
	err = SetLoginTokenPath(loginConfigPath)
	assert.NoErrorf(t, err, "Failed to set env", err)
	defer SetLoginTokenPath("")

	authorizer, err := GetSettingsFromEnvironment(server).GetAuthorizer()
	assert.NoErrorf(t, err, "Failed to create authorizer", err)

	_, err = makeAuthCall(t, authAddress, authorizer.WithRPCAuthorization(), authorizer.WithTransportAuthorization())
	assert.Equal(t, err.Error(), "rpc error: code = Unknown desc = Valid Token Required: InvalidToken", "Error Expected but missing ", err.Error())

	responsetls, err := makeTlsCall(t, tlsAddress, authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, responsetls.Name, "Hello From the Server!TLSServer")
}

func Test_TLSAuthServerFromEnvironmentTokenFileEmpty(t *testing.T) {
	server := "localhost"
	tlsPort := "9005"
	authPort := "9001"
	tlsAddress := server + ":" + tlsPort
	authAddress := server + ":" + authPort
	grpcServerAuth, jwtAuth, certPem, keyPem := getAuthServer(t)
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	assert.NoErrorf(t, err, "Failed to x509keypair", err)
	creds := getTlsCreds(t, tlsCert, certPem)
	grpcServertls := getGrpcServer(t, creds)
	go startHelloServer(grpcServertls, tlsAddress)
	defer grpcServertls.Stop()

	go startHollaServer(grpcServerAuth, jwtAuth, authAddress)
	defer grpcServerAuth.Stop()

	time.Sleep((time.Second * 3))

	dirPath := t.TempDir()
	accessFile := WssdConfig{}
	accessFile.CloudCertificate = marshal.ToBase64(string(certPem))
	accessFile.ClientKey = marshal.ToBase64(string(keyPem))
	accessFile.ClientCertificate = marshal.ToBase64(string(certPem))
	wssdConfigPath := filepath.Join(dirPath, "wssdconfig")
	err = marshal.ToJSONFile(&accessFile, wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to marshall json file", err)
	defer os.Remove(wssdConfigPath)

	err = SetCertificateDirPath("")
	assert.NoErrorf(t, err, "Failed to set env", err)
	err = SetCertificateFilePath(wssdConfigPath)
	assert.NoErrorf(t, err, "Failed to set env", err)
	defer SetCertificateFilePath("")
	err = SetLoginTokenPath("")
	assert.NoErrorf(t, err, "Failed to set env", err)

	authorizer, err := GetSettingsFromEnvironment(server).GetAuthorizer()
	assert.NoErrorf(t, err, "Failed to create authorizer", err)

	_, err = makeAuthCall(t, authAddress, authorizer.WithRPCAuthorization(), authorizer.WithTransportAuthorization())
	assert.Equal(t, err.Error(), "rpc error: code = Unknown desc = Valid Token Required: InvalidToken", "Error Expected but missing ", err.Error())

	responsetls, err := makeTlsCall(t, tlsAddress, authorizer.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, responsetls.Name, "Hello From the Server!TLSServer")
}

func Test_Authorizer_WithRPCAuthorization(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := mock.NewMockAuthorizer(ctrl)
	m.EXPECT().WithRPCAuthorization()
	m.WithRPCAuthorization()
}

// For poptoken auth, the workflow is much simpler compared to mTLS; the client is set to blindly trust
// the server's TLS certificate as it is already on a secure communication channel.
func Test_PopTokenAuthorizer(t *testing.T) {
	server := "localhost"
	port := "9005"
	address := server + ":" + port
	tlsCert, certPem, _ := getClientCert(t)
	creds := getDisableTlsCreds(t, tlsCert, certPem)
	grpcServer := getGrpcServer(t, creds)
	go startHelloServer(grpcServer, address)
	defer grpcServer.Stop()

	time.Sleep((time.Second * 3))
	provider, err := NewPopTokenAuthorizer()
	assert.NoErrorf(t, err, "Failed to create NewPopTokenAuthorizer", err)
	response, err := makeTlsCall(t, address, provider.WithTransportAuthorization())
	assert.NoErrorf(t, err, "Failed to make tls call", err)
	assert.Equal(t, response.Name, "Hello From the Server!TLSServer")
}

func Test_StripPortFromServerName(t *testing.T) {
	tests := []struct {
		name               string
		serverName         string
		expectedServerName string
	}{
		{
			name:               "server with no port",
			serverName:         "myhost",
			expectedServerName: "myhost",
		},
		{
			name:               "server with port",
			serverName:         "myhost:1234",
			expectedServerName: "myhost",
		},
		{
			name:               "server with port and whitespace",
			serverName:         " myhost : 1234 ",
			expectedServerName: "myhost",
		},
		{
			name:               "empty string",
			serverName:         "",
			expectedServerName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualServerName := stripPortFromServerName(tt.serverName)
			assert.Equal(t, tt.expectedServerName, actualServerName)
		})
	}
}
