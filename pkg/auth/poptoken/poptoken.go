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
)

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

// Implements the shr pop token generically. Callers of ths instance can add their own custom claims when generating the token.
type popToken struct {
	Header       PopTokenHeader
	Body         PopTokenBody
	refCnfBase64 string
	RSAKeyPair   *RsaKeyPair
}

const (
	TokenType = "pop"
)

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
func (pop *popToken) appendCustomClaimsToBody(customClaims map[string]interface{}) map[string]interface{} {

	bodyMap := make(map[string]interface{})

	// first convert the existing body to a map of interface.
	val := reflect.ValueOf(pop.Body)
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
func (pop *popToken) GenerateToken(token string, now time.Time, customClaims map[string]interface{}) (string, error) {

	pop.Body.Ts = now.Truncate(time.Second).Unix()
	pop.Body.At = token

	body, err := jsonToBase64(pop.appendCustomClaimsToBody(customClaims))
	if err != nil {
		return "", err
	}

	header, err := jsonToBase64(pop.Header)
	if err != nil {
		return "", err
	}

	signingStr := strings.Join([]string{header, body}, ".")

	signature, err := signPayload([]byte(signingStr), pop.RSAKeyPair.PrivateKey)
	if err != nil {
		return "", nil
	}

	return strings.Join([]string{signingStr, signature}, "."), nil
}

// Generate ReqCnf to be passed to Msal
func (pop *popToken) GetReqCnf() string {
	return pop.refCnfBase64
}

// Create a new instance of ShrPopToken. This generate a partial filled, generic shrpoptoken. The custom claims will be
// added later on in GenerateToken()
func NewPopToken(keyPair *RsaKeyPair) (*popToken, error) {
	pop := popToken{
		Header: PopTokenHeader{
			Alg: keyPair.Alg,
			Typ: TokenType,
		},
		Body: PopTokenBody{
			Cnf: Cnf{
				Jwk: Jwk{
					Kty: keyPair.Kty,
					N:   base64.RawURLEncoding.EncodeToString([]byte(keyPair.PublicKey.N.Bytes())),
					E:   exponential2Base64(keyPair.PublicKey.E),
				},
			},
		},
		RSAKeyPair: keyPair,
	}

	keyId, err := calculatePublicKeyId(&pop.Body.Cnf.Jwk)
	if err != nil {
		return nil, err
	}

	pop.Header.Kid = keyId

	refCnfb64, err := jsonToBase64(
		ReqCnf{
			Kid: keyId,
		})
	if err != nil {
		return nil, err
	}
	pop.refCnfBase64 = refCnfb64

	return &pop, err
}
