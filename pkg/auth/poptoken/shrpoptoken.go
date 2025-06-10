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

type ShrPopHeader struct {
	// RSA PS256?
	Alg string `json:"alg"`
	// key Id of public key
	Kid string `json:"kid"`
	// always pop
	Typ string `json:"typ"`
}

// https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
// contains the metadata use to calculate kid.
type JwkInner struct {
	// Exponent
	E string `json:"e"`
	// encryption
	Kty string `json:"kty"`
	// modulus
	N string `json:"n"`
}

type Jwk struct {
	JwkInner
	// public key kid
	Kid string `json:"kid"`
}

// https://datatracker.ietf.org/doc/html/rfc7800#section-3.2
type Cnf struct {
	Jwk     Jwk    `json:"jwk"`
	Xms_ksl string `json:"xms_ksl"`
}

type ReqCnf struct {
	Kid string `json:"kid"`
}

// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-signed-http-request-03#section-3
type ShrPopTokenBody struct {
	Cnf Cnf `json:"cnf"`
	// timestamp
	Ts int64 `json:"ts"`
	// access token
	At string `json:"at"`
	// random unique value to prevent replay attack. not used
	NonCe string `json:"nonce"`
}

// Implements the shr pop token generically. Callers of ths instance can add their own custom claims when generating the token.
type ShrPopToken struct {
	Header     ShrPopHeader
	Body       ShrPopTokenBody
	ReqCnf     ReqCnf
	RSAKeyPair *RsaKeyPair
}

const (
	TokenType = "pop"
)

func calculatePublicKeyId(jwkInner *JwkInner) (string, error) {
	// - https://tools.ietf.org/html/rfc7638#section-3.1
	jwkByte, err := json.Marshal(jwkInner)
	if err != nil {
		return "", err
	}
	jwk256 := sha256.Sum256(jwkByte)
	if err != nil {
		return "", err
	}
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
	ss := base64.URLEncoding.EncodeToString(bs)
	return ss
}

// Append custom claims to the existing ShrPopTokenBody.
func (pop *ShrPopToken) appendCustomClaimsToBody(customClaims map[string]interface{}) map[string]interface{} {

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
func (pop *ShrPopToken) GenerateToken(token string, now time.Time, customClaims map[string]interface{}) (string, error) {

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
func (pop *ShrPopToken) GetReqCnf() (string, error) {
	refCnfb64, err := jsonToBase64(pop.ReqCnf)
	if err != nil {
		return "", err
	}
	return refCnfb64, nil
}

// Create a new instance of ShrPopToken. This generate a partial filled, generic shrpoptoken. The custom claims will be
// added later on in GenerateToken()
func NewPopToken(keyPair *RsaKeyPair) (*ShrPopToken, error) {
	pop := ShrPopToken{
		Header: ShrPopHeader{
			Alg: keyPair.Alg,
			Typ: TokenType,
		},
		Body: ShrPopTokenBody{
			Cnf: Cnf{
				Jwk: Jwk{
					JwkInner: JwkInner{
						Kty: keyPair.Kty,
						E:   exponential2Base64(keyPair.PublicKey.E),
						N:   base64.URLEncoding.EncodeToString([]byte(keyPair.PublicKey.N.String())),
					},
				},
			},
		},
		ReqCnf:     ReqCnf{},
		RSAKeyPair: keyPair,
	}

	keyId, err := calculatePublicKeyId(&pop.Body.Cnf.Jwk.JwkInner)
	if err != nil {
		return nil, err
	}
	pop.Header.Kid = keyId
	pop.ReqCnf.Kid = keyId
	pop.Body.Cnf.Jwk.Kid = keyId

	return &pop, err
}
