package poptoken

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	refreshInterval        time.Duration = time.Hour * 8
	TokenType                            = "pop"
	DefaultRefreshInterval               = time.Hour * 8
	RsaSize                              = 2048
	Kty                                  = "RSA"
	Alg                                  = "RS256"
)

var (
	globalRsaKey                    *rsaKeyPair   = nil
	globalRefreshInterval           time.Duration = DefaultRefreshInterval
	globalLastRefreshRsaKeyDateTime time.Time     = time.Now()
)

type rsaKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type PopTokenHeader struct {
	// RSA PS256?
	Alg string `json:"alg"`
	// key Id of public key
	Kid string `json:"kid"`
	// always pop
	Typ string `json:"typ"`
}

// https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
// contains the metadata use to calculate kid.
type Jwk struct {
	// Exponent
	E string `json:"e"`
	// encryption
	Kty string `json:"kty"`
	// modulus
	N string `json:"n"`
}

// https://datatracker.ietf.org/doc/html/rfc7800#section-3.2
type Cnf struct {
	Jwk Jwk `json:"jwk"`
}

type ReqCnf struct {
	Kid string `json:"kid"`
}

// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-signed-http-request-03#section-3
type PopTokenBody struct {
	Cnf Cnf `json:"cnf"`
	// timestamp
	Ts int64 `json:"ts"`
	// access token
	At string `json:"at"`
}

// Implements the interface for MSAL SDK to callback when creating the poptoken.
// See AuthenticationScheme interface in https://github.com/AzureAD/microsoft-authentication-library-for-go/blob/main/apps/internal/oauth/ops/authority/authority.go#L146
type PopTokenAuthScheme struct {
	header       PopTokenHeader
	body         PopTokenBody
	reqCnfBase64 string
	claims       map[string]interface{}
	keyPair      *rsaKeyPair
}

// refresh the global rsa keypair once every 8 hours.
func generateRSAKeyPair(now time.Time) (*rsaKeyPair, error) {

	if globalRsaKey == nil || globalLastRefreshRsaKeyDateTime.Add(globalRefreshInterval).Before(now) {
		pKey, err := rsa.GenerateKey(rand.Reader, RsaSize)
		if err != nil {
			return nil, err
		}
		globalRsaKey = &rsaKeyPair{
			PrivateKey: pKey,
			PublicKey:  pKey.Public().(*rsa.PublicKey),
		}
		globalLastRefreshRsaKeyDateTime = now
	}
	return globalRsaKey, nil
}

func calculatePublicKeyId(jwk *Jwk) (string, error) {
	// - https://tools.ietf.org/html/rfc7638#section-3.1
	jwkByte, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	jwk256 := sha256.Sum256(jwkByte)
	return base64.RawURLEncoding.EncodeToString(jwk256[:]), nil
}

func jsonToBase64(v any) (string, error) {
	jsonValue, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(jsonValue), nil
}

func signPayload(payload []byte, rsaKey *rsa.PrivateKey) (string, error) {
	hash := sha256.New()
	_, err := hash.Write(payload)
	if err != nil {
		return "", err
	}
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sigBytes), nil
}

func exponential2Base64(e int) string {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(e))

	bs = bs[1:] // drop most significant byte - leaving least-significant 3-bytes
	ss := base64.RawURLEncoding.EncodeToString(bs)
	return ss
}

// Append custom claims to the existing ShrPopTokenBody.
func (p *PopTokenAuthScheme) appendCustomClaimsToBody(customClaims map[string]interface{}) map[string]interface{} {

	bodyMap := make(map[string]interface{})

	// first convert the existing body to a map of interface.
	val := reflect.ValueOf(p.body)
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		if name := strings.ToLower(typ.Field(i).Name); name != "" {
			bodyMap[name] = val.Field(i).Interface()
		}
	}
	// now append the custom claims
	for k, v := range customClaims {
		bodyMap[k] = v
	}

	return bodyMap
}

// Complete the poptoken creation by adding the custom claims and signing it.
func (p *PopTokenAuthScheme) generateToken(token string, now time.Time) (string, error) {

	p.body.Ts = now.Truncate(time.Second).Unix()
	p.body.At = token

	body, err := jsonToBase64(p.appendCustomClaimsToBody(p.claims))
	if err != nil {
		return "", err
	}

	header, err := jsonToBase64(p.header)
	if err != nil {
		return "", err
	}

	signingStr := strings.Join([]string{header, body}, ".")

	signature, err := signPayload([]byte(signingStr), p.keyPair.PrivateKey)
	if err != nil {
		return "", nil
	}

	return strings.Join([]string{signingStr, signature}, "."), nil
}

// Return the claim containg the pop token kid that will be added to the Entra access token.
func (p *PopTokenAuthScheme) TokenRequestParams() map[string]string {
	return map[string]string{
		"token_type": p.header.Typ,
		"req_cnf":    p.reqCnfBase64,
	}
}

// Return the keyId for MSAL to lookup for a cached access token. If it does not exist, MSAL will request a new access token
func (p *PopTokenAuthScheme) KeyID() string {
	return p.header.Kid
}

// Generate the pop token; adding in the accessToken generated by Entra.
func (p *PopTokenAuthScheme) FormatAccessToken(accessToken string) (string, error) {
	return p.generateToken(accessToken, time.Now())
}

// Return the token type. Must be "pop"
func (p *PopTokenAuthScheme) AccessTokenType() string {
	return p.header.Typ
}

// Create a new instance of PopTokenAuthScheme. Pass in the custom claims to be set in the pop token here, e.g. resourceId
func NewPopTokenAuthScheme(claims map[string]interface{}) (*PopTokenAuthScheme, error) {

	keyPair, err := generateRSAKeyPair(time.Now())
	if err != nil {
		return nil, err
	}

	popTokenScheme := &PopTokenAuthScheme{
		header: PopTokenHeader{
			Alg: Alg,
			Typ: TokenType,
		},
		body: PopTokenBody{
			Cnf: Cnf{
				Jwk: Jwk{
					Kty: Kty,
					N:   base64.RawURLEncoding.EncodeToString([]byte(keyPair.PublicKey.N.Bytes())),
					E:   exponential2Base64(keyPair.PublicKey.E),
				},
			},
		},
		keyPair: keyPair,
		claims:  claims,
	}

	keyId, err := calculatePublicKeyId(&popTokenScheme.body.Cnf.Jwk)
	if err != nil {
		return nil, errors.Wrapf(err, "faild to generate kid")
	}

	popTokenScheme.header.Kid = keyId

	reqCnfb64, err := jsonToBase64(
		ReqCnf{
			Kid: keyId,
		})
	if err != nil {
		return nil, errors.Wrapf(err, "faild to generate base64 representation of req_cnf")
	}
	popTokenScheme.reqCnfBase64 = reqCnfb64

	return popTokenScheme, nil
}
