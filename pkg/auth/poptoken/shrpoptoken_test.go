package poptoken

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testStruct struct {
	StrValue string `json:"str"`
	IntValue int    `json:"int"`
}

// the pop token is partially filled out upon calling NewPopToken
func Test_ShrPopTokenNewPopToken(t *testing.T) {
	keypair, err := getKeyPair()
	assert.Nil(t, err)

	pop, err := NewPopToken(keypair)
	assert.Nil(t, err)

	// calculate kid
	expectedKid, err := calculatePublicKeyId(&pop.Body.Cnf.Jwk.JwkInner)
	assert.Nil(t, err)

	// check header
	assert.Equal(t, Alg, pop.Header.Alg)
	assert.Equal(t, TokenType, pop.Header.Typ)
	assert.Equal(t, expectedKid, pop.Header.Kid)

	// check body
	expectedE := exponential2Base64(keypair.PrivateKey.E)
	expectedN := base64.URLEncoding.EncodeToString([]byte(keypair.PublicKey.N.String()))
	assert.Equal(t, expectedE, pop.Body.Cnf.Jwk.E)
	assert.Equal(t, expectedN, pop.Body.Cnf.Jwk.N)
	assert.Equal(t, keypair.Kty, pop.Body.Cnf.Jwk.Kty)
	assert.Equal(t, expectedKid, pop.Body.Cnf.Jwk.Kid)

	// check ReqCnf
	assert.Equal(t, expectedKid, pop.ReqCnf.Kid)
}

func Test_ShrPopTokenGenerateToken(t *testing.T) {
	keypair, err := getKeyPair()
	assert.Nil(t, err)

	pop, err := NewPopToken(keypair)
	assert.Nil(t, err)

	expectedAccessToken := "myFakeAccessToken"
	expectedTimeStamp, err := time.Parse(time.RFC3339, "2025-12-01T15:00:00Z")
	assert.Nil(t, err)

	expectedResourceIdValue := "1234"
	customClaims := map[string]interface{}{"resourceId": expectedResourceIdValue}

	// calculate kid
	expectedKid, err := calculatePublicKeyId(&pop.Body.Cnf.Jwk.JwkInner)
	assert.Nil(t, err)

	// Generate the token and validate its content
	popToken, err := pop.GenerateToken(expectedAccessToken, expectedTimeStamp, customClaims)
	assert.Nil(t, err)

	toks := strings.Split(popToken, ".")
	assert.Equal(t, 3, len(toks))

	// validate header.
	header, err := decodeFromBase64[ShrPopHeader](toks[0])
	assert.Nil(t, err)
	assert.Equal(t, Alg, header.Alg)
	assert.Equal(t, TokenType, header.Typ)
	assert.Equal(t, expectedKid, header.Kid)

	// validate body
	body, err := decodeFromBase64[nodeAgentPopTokenBody](toks[1])
	assert.Nil(t, err)
	assert.Equal(t, expectedTimeStamp.Truncate(time.Second).Unix(), body.Ts)
	assert.Equal(t, expectedResourceIdValue, body.ResourceId)
	assert.Equal(t, expectedAccessToken, body.At)
	assert.Equal(t, expectedKid, body.Cnf.Jwk.Kid)

	// validate signature.
	signature, err := base64.RawURLEncoding.DecodeString(toks[2])
	assert.Nil(t, err)

	signingStr := strings.Join([]string{toks[0], toks[1]}, ".")
	err = isSignatureValid(&signingStr, signature, &body.Cnf)
	assert.Nil(t, err)
}

func Test_ShrPopTokenAppendCustomClaims(t *testing.T) {
	keypair, err := getKeyPair()
	assert.Nil(t, err)

	pop, err := NewPopToken(keypair)
	assert.Nil(t, err)

	expectedStringValue := "string"
	expectedIntegerValue := 1234
	expectedStrArrValue := []string{"hello", "world"}
	expectedStructValue := testStruct{StrValue: "string", IntValue: 1234}

	customClaims := map[string]interface{}{
		"string":   expectedStringValue,
		"integer":  expectedIntegerValue,
		"strArray": expectedStrArrValue,
		"struct":   expectedStructValue,
	}

	actualClaims := pop.appendCustomClaimsToBody(customClaims)

	tmp, ok := actualClaims["string"]
	assert.True(t, ok)
	actualstringValue, ok := tmp.(string)
	assert.True(t, ok)
	assert.Equal(t, expectedStringValue, actualstringValue)

	tmp, ok = actualClaims["integer"]
	assert.True(t, ok)
	actualIntegerValue, ok := tmp.(int)
	assert.True(t, ok)
	assert.Equal(t, expectedIntegerValue, actualIntegerValue)

	tmp, ok = actualClaims["strArray"]
	assert.True(t, ok)
	actualStrArrValue, ok := tmp.([]string)
	assert.True(t, ok)
	assert.Equal(t, expectedStrArrValue, actualStrArrValue)

	tmp, ok = actualClaims["struct"]
	assert.True(t, ok)
	actualStructValue, ok := tmp.(testStruct)
	assert.True(t, ok)
	assert.Equal(t, expectedStructValue, actualStructValue)

	// finally sanity check that these custom claims can be converted to json
	_, err = jsonToBase64(actualClaims)
	assert.Nil(t, err)
}

func Test_ShrPopTokenGetReqCnf(t *testing.T) {
	keypair, err := getKeyPair()
	assert.Nil(t, err)

	pop, err := NewPopToken(keypair)
	assert.Nil(t, err)

	expectedReqCnfBase64, err := jsonToBase64(pop.ReqCnf)
	assert.Nil(t, err)

	actualreqCnfBase64, err := pop.GetReqCnf()
	assert.Equal(t, expectedReqCnfBase64, actualreqCnfBase64)
}

func Test_ShrPopTokenExponential2Base64(t *testing.T) {
	e := 65537
	base64 := exponential2Base64(e)
	// this is the encoded value of a well known exponential value
	assert.Equal(t, "AQAB", base64)
}

func Test_ShrPopTokenCalculatePublicKeyId(t *testing.T) {
	jwkinner := JwkInner{
		Kty: "RSA",
		E:   "AQAB",
		N:   "MjM1MDg5MDU4MzgxMDg3OTI5NTU3NjM1ODg4NTA3NDE5OTAwNzc0MzkzNzQ5NDcwNzcwMjA2MDIxNjMyNzk5NzYxNDM4NTczMjc3NTA0NzI4ODkzNDUzNjU0NDU0NjMxMjcxNjQ0MTAwMDM0NzUzNzU2MTEyMjkzODYzMDYxMjk5MDQxNzI5OTc0MDg5OTk2OTEzNTY4MjM5OTc0NDMwNTExODI3MDgyNDAzMDQxNDMxMTQ5ODA4ODc4NjE5NTc5MjcwMjAxNjc3ODM1NTQ0NDI3NDMwMDczODI2OTAwODk2MzcxNTM2NzE5NDQyNTUxNzIzNTM5MTg4OTU2MDc4MzI0MzYxNDM4MDEzNjA3OTI0NzMyNTUxMDg5ODU3NjQ1NDA0MTIyMTk3ODUwNjkyMjEyMTk4OTMxMDU1NTkzOTk4NzYyMjIwODg1NDg5NzE4MjQxNDAxMTg2MTMwMzExODAwMDQ2NjEwMjk0MDIzMzQ1MTA1NjE4ODY0ODc0OTgzNzU2NTMzMTY0OTk5MTg1NDk4ODIwOTY3NjYyNjM1NTUxMjk0NTkzNDEwNzc5MzUwODg2MjMxODkyMTc0NTcwODkxNDU4MjIwNzIwMzI5MTg3OTA3NzAxMzMzMDU1NzM0ODk0NjU3MDYzOTMzMzA3MTUwNjgzMTk1NjkyOTk0MzAxMjUxODUwNzUwMTg2MzI5MzM4ODk2NjY3OTQyMDE0OTcwODY3MTAzMTgxNTA5NDAxMTAwMzUwMzk5MDE3MDI3MTI3MTAwMDM5OTIwNjgwNjExNjcxNTQ3MDE1ODM2NzIyMTU1OTgxMTE=",
	}
	keyId, err := calculatePublicKeyId(&jwkinner)
	assert.Nil(t, err)
	assert.Equal(t, "a0CyVS__Npcx4GXYm1OCoxrlboOWKF02MXzSSh92ckY", keyId)
}

func Test_ShrPopTokenSignPayload(t *testing.T) {
	keypair, err := getKeyPair()
	assert.Nil(t, err)

	payload := []byte("ThisIsMyTestPayLoad")

	sig, err := signPayload(payload, keypair.PrivateKey)
	assert.Nil(t, err)

	//now verify the signature using the public key
	sigDecode, err := base64.RawURLEncoding.DecodeString(sig)
	hash := sha256.New()
	hash.Write(payload)
	err = rsa.VerifyPKCS1v15(keypair.PublicKey, crypto.SHA256, hash.Sum(nil), sigDecode)
	assert.Nil(t, err)
}

func getKeyPair() (*RsaKeyPair, error) {

	pKey, err := generatePrivateKey()
	if err != nil {
		return nil, err
	}

	return &RsaKeyPair{
		PrivateKey: pKey,
		PublicKey:  pKey.Public().(*rsa.PublicKey),
		RsaSize:    RsaSize,
		Kty:        Kty,
		Alg:        Alg,
	}, nil
}
