package poptoken

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testClaimName = "test"
	testValue     = "value"
)

var (
	testClaims = map[string]interface{}{testClaimName: testValue}
)

type TestPopTokenSchemeBody struct {
	PopTokenBody
	Test string `json:"test"` // must matchtestClaimName
}

type testStruct struct {
	StrValue string
	IntValue int
}

func Test_PopTokenAuthSchemeNew(t *testing.T) {

	pop, err := NewPopTokenAuthScheme(testClaims)
	assert.Nil(t, err)

	// calculate kid
	expectedKid, err := calculatePublicKeyId(&pop.body.Cnf.Jwk)
	assert.Nil(t, err)

	// check header
	assert.Equal(t, Alg, pop.header.Alg)
	assert.Equal(t, TokenType, pop.header.Typ)
	assert.Equal(t, expectedKid, pop.header.Kid)

	// check body
	expectedE := exponential2Base64(pop.keyPair.PrivateKey.E)
	expectedN := base64.RawURLEncoding.EncodeToString([]byte(pop.keyPair.PublicKey.N.Bytes()))
	assert.Equal(t, expectedE, pop.body.Cnf.Jwk.E)
	assert.Equal(t, expectedN, pop.body.Cnf.Jwk.N)

	//check claims
	actualValue, ok := pop.claims[testClaimName]
	assert.True(t, ok)
	assert.Equal(t, testValue, actualValue)
}

func Test_PopTokenAuthSchemeGenerateToken(t *testing.T) {
	pop, err := NewPopTokenAuthScheme(testClaims)
	assert.Nil(t, err)

	expectedAccessToken := "myFakeAccessToken"
	expectedTimeStamp, err := time.Parse(time.RFC3339, "2025-12-01T15:00:00Z")
	assert.Nil(t, err)

	expectedKid, err := calculatePublicKeyId(&pop.body.Cnf.Jwk)
	assert.Nil(t, err)

	// Generate the token and validate its content
	popToken, err := pop.generateToken(expectedAccessToken, expectedTimeStamp)
	assert.Nil(t, err)

	toks := strings.Split(popToken, ".")
	assert.Equal(t, 3, len(toks))

	// validate header.
	header, err := decodeFromBase64[PopTokenHeader](toks[0])
	assert.Nil(t, err)
	assert.Equal(t, Alg, header.Alg)
	assert.Equal(t, TokenType, header.Typ)
	assert.Equal(t, expectedKid, header.Kid)

	// validate body
	body, err := decodeFromBase64[TestPopTokenSchemeBody](toks[1])
	assert.Nil(t, err)
	assert.Equal(t, expectedTimeStamp.Truncate(time.Second).Unix(), body.Ts)
	assert.Equal(t, testValue, body.Test)
	assert.Equal(t, expectedAccessToken, body.At)

	// validate signature.
	signature, err := base64.RawURLEncoding.DecodeString(toks[2])
	assert.Nil(t, err)

	signingStr := strings.Join([]string{toks[0], toks[1]}, ".")
	err = isSignatureValid(&signingStr, signature, &body.Cnf)
	assert.Nil(t, err)
}

func Test_PopTokenAuthSchemeTokenRequestParams(t *testing.T) {
	pop, err := NewPopTokenAuthScheme(testClaims)
	assert.Nil(t, err)

	expectedCnfBase64, err := jsonToBase64(
		ReqCnf{
			Kid: pop.header.Kid,
		})
	assert.Nil(t, err)

	requestParams := pop.TokenRequestParams()

	// we expect these two entries
	tokType, ok := requestParams["token_type"]
	assert.True(t, ok)
	assert.Equal(t, TokenType, tokType)

	actualReqCnf, ok := requestParams["req_cnf"]
	assert.True(t, ok)
	assert.Equal(t, expectedCnfBase64, actualReqCnf)
}

func Test_PopTokenAuthSchemeAppendCustomClaims(t *testing.T) {
	pop, err := NewPopTokenAuthScheme(testClaims)
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

func Test_PopTokenAuthSchemeExponential2Base64(t *testing.T) {
	e := 65537
	base64 := exponential2Base64(e)
	// this is the encoded value of a well known exponential value
	assert.Equal(t, "AQAB", base64)
}

func Test_PopTokenAuthSchemeCalculatePublicKeyId(t *testing.T) {
	jwk := Jwk{
		Kty: "RSA",
		E:   "AQAB",
		N:   "MjM1MDg5MDU4MzgxMDg3OTI5NTU3NjM1ODg4NTA3NDE5OTAwNzc0MzkzNzQ5NDcwNzcwMjA2MDIxNjMyNzk5NzYxNDM4NTczMjc3NTA0NzI4ODkzNDUzNjU0NDU0NjMxMjcxNjQ0MTAwMDM0NzUzNzU2MTEyMjkzODYzMDYxMjk5MDQxNzI5OTc0MDg5OTk2OTEzNTY4MjM5OTc0NDMwNTExODI3MDgyNDAzMDQxNDMxMTQ5ODA4ODc4NjE5NTc5MjcwMjAxNjc3ODM1NTQ0NDI3NDMwMDczODI2OTAwODk2MzcxNTM2NzE5NDQyNTUxNzIzNTM5MTg4OTU2MDc4MzI0MzYxNDM4MDEzNjA3OTI0NzMyNTUxMDg5ODU3NjQ1NDA0MTIyMTk3ODUwNjkyMjEyMTk4OTMxMDU1NTkzOTk4NzYyMjIwODg1NDg5NzE4MjQxNDAxMTg2MTMwMzExODAwMDQ2NjEwMjk0MDIzMzQ1MTA1NjE4ODY0ODc0OTgzNzU2NTMzMTY0OTk5MTg1NDk4ODIwOTY3NjYyNjM1NTUxMjk0NTkzNDEwNzc5MzUwODg2MjMxODkyMTc0NTcwODkxNDU4MjIwNzIwMzI5MTg3OTA3NzAxMzMzMDU1NzM0ODk0NjU3MDYzOTMzMzA3MTUwNjgzMTk1NjkyOTk0MzAxMjUxODUwNzUwMTg2MzI5MzM4ODk2NjY3OTQyMDE0OTcwODY3MTAzMTgxNTA5NDAxMTAwMzUwMzk5MDE3MDI3MTI3MTAwMDM5OTIwNjgwNjExNjcxNTQ3MDE1ODM2NzIyMTU1OTgxMTE=",
	}
	keyId, err := calculatePublicKeyId(&jwk)
	assert.Nil(t, err)
	assert.Equal(t, "a0CyVS__Npcx4GXYm1OCoxrlboOWKF02MXzSSh92ckY", keyId)
}

func Test_PopTokenAuthSchemeSignPayload(t *testing.T) {
	keypair, err := generateKeyPair()
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

func Test_PopTokenAuthSchemeGenerateRsaKeyPair(t *testing.T) {

	now, err := time.Parse(time.RFC3339, "2025-12-01T15:00:00Z")

	keyPair1, err := generateRSAKeyPair(now)
	assert.Nil(t, err)
	assert.NotNil(t, keyPair1)

	// now simulate getting a second keypair < refreshInterval; keyPair2 should be the same
	keyPair2, err := generateRSAKeyPair(now)
	assert.Nil(t, err)
	assert.NotNil(t, keyPair2)
	assert.Equal(t, keyPair1.PrivateKey.N, keyPair2.PrivateKey.N)

	// now simulate getting a third keypair > refreshInterval; keyPair3 should be different from 1 and 2.
	newNow := now.Add(globalRefreshInterval).Add(time.Minute)
	keyPair3, err := generateRSAKeyPair(newNow)
	assert.Nil(t, err)
	assert.NotNil(t, keyPair3)
	assert.NotEqual(t, keyPair1.PrivateKey.N, keyPair3.PrivateKey.N)
	assert.NotEqual(t, keyPair2.PrivateKey.N, keyPair3.PrivateKey.N)

	// now try again; keypair4 == keypair3
	keyPair4, err := generateRSAKeyPair(newNow)
	assert.Nil(t, err)
	assert.NotNil(t, keyPair4)
	assert.Equal(t, keyPair3.PrivateKey.N, keyPair4.PrivateKey.N)
}

func generateKeyPair() (*rsaKeyPair, error) {
	pKey, err := rsa.GenerateKey(rand.Reader, RsaSize)
	if err != nil {
		return nil, err
	}
	return &rsaKeyPair{
		PrivateKey:      pKey,
		PublicKey:       pKey.Public().(*rsa.PublicKey),
		CreatedDateTime: time.Now(),
	}, nil
}
