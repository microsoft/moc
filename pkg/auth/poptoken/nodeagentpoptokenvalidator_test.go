package poptoken

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func Test_NodeAgentPopTokenValidatorAppendUrl(t *testing.T) {

	tests := []struct {
		name        string
		url         string
		postfix     string
		expectedUrl string
	}{
		{
			name:        "without backslash at end",
			url:         "http://localhost",
			postfix:     "myapi",
			expectedUrl: "http://localhost/myapi",
		},
		{
			name:        "with backslash at end",
			url:         "http://localhost/",
			postfix:     "myapi",
			expectedUrl: "http://localhost/myapi",
		}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualUrl := appendUrl(tt.url, tt.postfix)
			assert.Equal(t, tt.expectedUrl, actualUrl)
		})
	}
}

func Test_NodeAgentPopTokenValidatorIsTokenExpire(t *testing.T) {
	tokenIssuedAt, err := time.Parse(time.RFC3339, "2025-12-01T15:00:00Z")
	assert.Nil(t, err)
	tokenIssuedAtInt := tokenIssuedAt.Truncate(time.Second).Unix()

	tests := []struct {
		name         string
		tokenCheckAt time.Time
		clockSkew    time.Duration
		shouldPass   bool
	}{
		{
			name: "token valid",
			// set token evaluation time to be 1 second after token was issued, token is valid.
			tokenCheckAt: tokenIssuedAt.Add(time.Second * 1),
			clockSkew:    0,
			shouldPass:   true,
		},
		{
			name: "token expired",
			// set token evaluation time to be 10 seconds after max valid period. token has expired.
			tokenCheckAt: tokenIssuedAt.Add(PopTokenValidInterval).Add(time.Second * 10),
			clockSkew:    0,
			shouldPass:   false,
		},
		{
			name: "token pass due to clock skew",
			// set token evaluation time to be 10 seconds after max valid period. token should have expired
			// like previous test, but passes thanks to the allowed clock skew of 11 seconds.
			tokenCheckAt: tokenIssuedAt.Add(PopTokenValidInterval).Add(time.Second * 10),
			clockSkew:    time.Second * 11,
			shouldPass:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isTokenExpire(tokenIssuedAtInt, tt.tokenCheckAt, tt.clockSkew)
			if tt.shouldPass {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

func Test_NodeAgentPopTokenValidatorIsHeaderValid(t *testing.T) {
	tests := []struct {
		name       string
		header     PopTokenHeader
		shouldPass bool
	}{
		{
			name:       "valid header",
			shouldPass: true,
			header:     PopTokenHeader{Alg: Alg, Typ: TokenType},
		},
		{
			name:       "invalid alg",
			shouldPass: false,
			header:     PopTokenHeader{Alg: "RSA123", Typ: TokenType},
		},
		{
			name:       "invalid typ",
			shouldPass: false,
			header:     PopTokenHeader{Alg: Alg, Typ: "jwt"},
		},
		{
			name:       "empty header",
			shouldPass: false,
			header:     PopTokenHeader{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isHeaderValid(&tt.header)
			if tt.shouldPass {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

func Test_NodeAgentPopTokenValidatorIsTokenReused(t *testing.T) {
	nonceCache := &FakeNonceCache{Exists: false}

	// for this test, we only care about setting the noncecache
	popTokenValidator, err := NewPopTokenValidator("", "", "", []string{"aud"}, "", "", nil, nonceCache)
	assert.Nil(t, err)

	// simulate nonce entry does not exists in cache, i.e. we have not seen the token before
	nonceCache.Exists = false
	err = popTokenValidator.isTokenReused("myId", time.Now())
	assert.Nil(t, err)

	// simulate nonce entry exists in cache, i.e. same token is reused, potentially a replay token
	nonceCache.Exists = true
	err = popTokenValidator.isTokenReused("myId", time.Now())
	assert.NotNil(t, err)

	// simulate missing nonce. we will reject token
	nonceCache.Exists = false
	err = popTokenValidator.isTokenReused("", time.Now())
	assert.NotNil(t, err)
}

func Test_NodeAgentPopTokenValidatorIsSignatureValid(t *testing.T) {
	keypair, err := getKeyPair()
	assert.Nil(t, err)

	payload := []byte("ThisIsPayload")
	payloadStr := string(payload)

	sigEncoded, err := signPayload(payload, keypair.PrivateKey)
	assert.Nil(t, err)
	sig, err := base64.RawURLEncoding.DecodeString(sigEncoded)
	assert.Nil(t, err)

	cnf := publicKeyToCnf(keypair)

	// signature is correctly validated given correct payload and public key.
	err = isSignatureValid(&payloadStr, sig, cnf)
	assert.Nil(t, err)

	// simulate a mangled payload, expect failure
	badPayload := payloadStr + "baddata"

	err = isSignatureValid(&badPayload, sig, cnf)
	assert.NotNil(t, err)

	// simulate bad sig, expect failure
	badSig := string(sig) + "1111"

	err = isSignatureValid(&payloadStr, []byte(badSig), cnf)
	assert.NotNil(t, err)

	// simulate wrong public key, expect failure
	newKeyPair, err := getKeyPair()
	assert.Nil(t, err)
	misMatachCnf := publicKeyToCnf(newKeyPair)

	err = isSignatureValid(&payloadStr, sig, misMatachCnf)
	assert.NotNil(t, err)
}

func Test_NodeAgentPopTokenValidatorbase64ToExponential(t *testing.T) {
	encodedExponential := "AQAB"
	e, err := base64ToExponential(encodedExponential)
	assert.Nil(t, err)
	// this is the decoded value of a well known exponential value
	assert.Equal(t, 65537, e)
}

func Test_NodeAgentPopTokenValidatorIsCustomClaimsValid(t *testing.T) {
	expectedNodeId := "myNodeId"
	expectedGrpcObjectId := "myObjectId"

	tests := []struct {
		name               string
		actualNodeId       string
		actualGrpcObjectId string
		shouldPass         bool
	}{
		{
			name:               "valid nodeId and objectId claims",
			actualNodeId:       expectedNodeId,
			actualGrpcObjectId: expectedGrpcObjectId,
			shouldPass:         true,
		},
		{
			name:               "invalid nodeId claim",
			actualNodeId:       "somethingelse",
			actualGrpcObjectId: expectedGrpcObjectId,
			shouldPass:         false,
		},
		{
			name:               "missing nodeId claim",
			actualNodeId:       "",
			actualGrpcObjectId: expectedGrpcObjectId,
			shouldPass:         false,
		},
		{
			name:               "invalid grpcObjectId claim",
			actualNodeId:       expectedNodeId,
			actualGrpcObjectId: "somethingelse",
			shouldPass:         false,
		},
		{
			name:               "missing grpcObjectId claim",
			actualNodeId:       expectedNodeId,
			actualGrpcObjectId: "",
			shouldPass:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// for this test, we only care about initializeing the custom claims
			popTokenValidator, err := NewPopTokenValidator(expectedNodeId, expectedGrpcObjectId, "", []string{"aud"}, "", "", nil, nil)
			assert.Nil(t, err)
			// likewise we only set the custom claims in the poptoken body
			popTokenBody := NodeAgentPopTokenBody{NodeId: tt.actualNodeId, GrpcObjectId: tt.actualGrpcObjectId}

			err = popTokenValidator.isCustomClaimsValid(&popTokenBody)
			if tt.shouldPass {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

// Test the access token validation against a range of invalid claims.
func Test_NodeAgentPopTokenValidatorParseAndValidateAccessToken(t *testing.T) {
	expectedAuthorityUrl := "https://login.fake.microsoftonline.com"
	expectedTenantId := "cmpTenantId"
	expectedClientId := "cmpClientId"
	expectedAudience := "cmpAudience"
	expectedIssuedTime := time.Now()
	expectedPopTokenKid := "defaultKid"

	defaultPKey, _ := getPrivateKey()
	defaultJwkMgr := &FakeJwrMgr{PublicKey: &defaultPKey.PublicKey}
	nonceCache := &FakeNonceCache{Exists: false}
	// By default, the accesstoken and validator will use the same expected values as listed above
	// hence the access token validation will succeeded.

	// test is setup such that each invalid claim declared will override the access token's ciaim, causing it to be invalid.
	tests := []struct {
		name                string
		invalidAuthorityUrl string
		invalidTenantId     string
		invalidClientId     string
		invalidAudience     string
		invalidIssuerUrl    string
		invalidPopTokenKid  string
		tokenVersion        string
		isInvalidSigning    bool
		isMissingKid        bool
		isExpiredToken      bool
		shouldPass          bool
	}{
		{
			name:         "valid access token v1",
			tokenVersion: TokenVersion1,
			shouldPass:   true,
		},
		{
			name:         "valid access token v1",
			tokenVersion: TokenVersion2,
			shouldPass:   true,
		},
		{
			name:            "invalid tenantId",
			tokenVersion:    TokenVersion2,
			invalidTenantId: "badTenantId",
			shouldPass:      false,
		},
		{
			name:            "invalid clientId",
			tokenVersion:    TokenVersion2,
			invalidClientId: "badClientId",
			shouldPass:      false,
		},
		{
			name:            "invalid audience",
			tokenVersion:    TokenVersion2,
			invalidAudience: "badAudienceId",
			shouldPass:      false,
		},
		{
			name:               "invalid pop token id",
			tokenVersion:       TokenVersion2,
			invalidPopTokenKid: "badPopTokenId",
			shouldPass:         false,
		},
		{
			name:             "invalid signing",
			tokenVersion:     TokenVersion2,
			isInvalidSigning: true,
			shouldPass:       false,
		},
		{
			name:           "token expired",
			tokenVersion:   TokenVersion2,
			isExpiredToken: true,
			shouldPass:     false,
		},
		{
			name:         "missing kid",
			tokenVersion: TokenVersion2,
			isMissingKid: true,
			shouldPass:   false,
		},
		{
			name:                "invalid issuer",
			tokenVersion:        TokenVersion2,
			invalidAuthorityUrl: "https://bad.issuer",
			shouldPass:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenantId := expectedTenantId
			if tt.invalidTenantId != "" {
				tenantId = tt.invalidTenantId
			}

			clientId := expectedClientId
			if tt.invalidClientId != "" {
				clientId = tt.invalidClientId
			}

			// to simulate expired token, we make it invalid after one second and sleep before validating token
			newexpiry := time.Second
			expiredTime := expectedIssuedTime.Add(time.Hour)
			if tt.isExpiredToken {
				expiredTime = expectedIssuedTime.Add(newexpiry)
			}

			tokenVersion := tt.tokenVersion

			authorityUrl := expectedAuthorityUrl
			if tt.invalidAuthorityUrl != "" {
				authorityUrl = tt.invalidAuthorityUrl
			}

			audience := expectedAudience
			if tt.invalidAudience != "" {
				audience = tt.invalidAudience
			}

			issuserUrl := fmt.Sprintf("%s/%s", authorityUrl, tenantId)
			if tokenVersion == TokenVersion2 {
				issuserUrl = fmt.Sprintf("%s/v2.0", issuserUrl)
			}

			popTokenKid := expectedPopTokenKid
			if tt.invalidPopTokenKid != "" {
				popTokenKid = tt.invalidPopTokenKid
			}

			jwkMgr := defaultJwkMgr
			if tt.isInvalidSigning {
				newPKey, _ := getPrivateKey()
				jwkMgr = &FakeJwrMgr{PublicKey: &newPKey.PublicKey}
			}

			if tt.isMissingKid {
				jwkMgr = &FakeJwrMgr{Err: fmt.Errorf("failed to find key")}
			}

			// access token to be generated can contain invalid claims depending on the test param,
			// by default it will use the same data as the token validator.
			claims := AccessTokenCustomClaims{
				Tid:          tenantId,
				ReqCnf:       ReqCnf{Kid: popTokenKid},
				Azp:          clientId,
				AppId:        clientId,
				TokenVersion: tokenVersion,
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    issuserUrl,
					ExpiresAt: jwt.NewNumericDate(expiredTime),
					IssuedAt:  jwt.NewNumericDate(expectedIssuedTime),
					NotBefore: jwt.NewNumericDate(expectedIssuedTime),
					Audience:  jwt.ClaimStrings{audience},
					Subject:   clientId,
				},
			}

			// The token validator is set to the expected values, except for invalid jwk
			tokenValidator, err := NewPopTokenValidator(
				"notused", // this is not tested here.
				"notused", // this is not tested here.
				expectedTenantId,
				[]string{expectedAudience},
				expectedClientId,
				expectedAuthorityUrl,
				jwkMgr,
				nonceCache)
			assert.Nil(t, err)

			s, err := generateAccessToken(&claims, defaultPKey)
			assert.Nil(t, err)

			// sleep for a while to ensure token expires
			if tt.isExpiredToken {
				time.Sleep(newexpiry * 2)
			}

			err = tokenValidator.parseAndValidateAccessToken(s, expectedPopTokenKid)
			if tt.shouldPass {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

// Test the overall validate function. We have already tested the individual functions that makes up this call
// this is just a simple test to validate end to end.
func Test_NodeAgentPopTokenValidatorValidate(t *testing.T) {
	authorityUrl := "https://login.fake.microsoftonline.com"
	nodeId := "nodeId"
	grpcObjectId := "objectId"
	tenantId := "cmpTenantId"
	clientId := "cmpClientId"
	audience := "cmpAudience"
	issuedTime := time.Now()
	expiredTime := issuedTime.Add(time.Hour)
	tokenVersion := TokenVersion2
	issuerUrl := fmt.Sprintf("%s/%s/v2.0", authorityUrl, tenantId)

	accessTokenPKey, err := getPrivateKey()
	assert.Nil(t, err)
	jwkMgr := &FakeJwrMgr{PublicKey: &accessTokenPKey.PublicKey}
	nonceCache := &FakeNonceCache{Exists: false}

	rsaKeyPair, err := getKeyPair()
	assert.Nil(t, err)

	// partial generate pop token, we need to add the popKid into the accesstoken
	popToken, err := NewPopToken(rsaKeyPair)
	assert.Nil(t, err)

	// Generate access token
	claims := AccessTokenCustomClaims{
		Tid:          tenantId,
		ReqCnf:       ReqCnf{Kid: popToken.Header.Kid},
		Azp:          clientId,
		AppId:        clientId,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuerUrl,
			ExpiresAt: jwt.NewNumericDate(expiredTime),
			IssuedAt:  jwt.NewNumericDate(issuedTime),
			NotBefore: jwt.NewNumericDate(issuedTime),
			Audience:  jwt.ClaimStrings{audience},
			Subject:   clientId,
		},
	}
	at, err := generateAccessToken(&claims, accessTokenPKey)
	assert.Nil(t, err)

	// Generate pop token
	pt, err := popToken.GenerateToken(at, time.Now(), map[string]interface{}{"nodeId": nodeId, "p": grpcObjectId, "nonce": "nonceId"})
	assert.Nil(t, err)

	// validate poptoken
	tokenValidator, err := NewPopTokenValidator(
		nodeId,
		grpcObjectId,
		tenantId,
		[]string{audience},
		clientId,
		authorityUrl,
		jwkMgr,
		nonceCache)
	assert.Nil(t, err)

	err = tokenValidator.Validate(pt)
	assert.Nil(t, err)
}

func generateAccessToken(claims *AccessTokenCustomClaims, privateKey *rsa.PrivateKey) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   claims.Issuer,
		"sub":   claims.Subject,
		"aud":   claims.Audience,
		"exp":   claims.ExpiresAt,
		"nbf":   claims.NotBefore,
		"iat":   claims.IssuedAt,
		"cnf":   claims.ReqCnf,
		"azp":   claims.Azp,
		"appId": claims.AppId,
		"ver":   claims.TokenVersion,
		"tid":   claims.Tid,
	})

	// we don't care about the actual kid value here since we use a fake jwkMgr that ignores the kidm but we do
	// expect it to be present in the header.
	tok.Header["kid"] = "notused"
	at, err := tok.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return at, err
}

// fake jwkMgr that will return either the public key or error
type FakeJwrMgr struct {
	PublicKey *rsa.PublicKey
	Err       error
}

func (j *FakeJwrMgr) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	if j.Err != nil {
		return nil, j.Err
	} else {
		return j.PublicKey, nil
	}
}

// fake nonceCache that we can set to return true or false at will.
type FakeNonceCache struct {
	Exists bool
}

func (n *FakeNonceCache) IsNonceExists(nonceId string, now time.Time) bool {
	return n.Exists
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RsaSize)
}

func publicKeyToCnf(keyPair *RsaKeyPair) *Cnf {
	return &Cnf{
		Jwk: Jwk{
			Kty: keyPair.Kty,
			E:   exponential2Base64(keyPair.PublicKey.E),
			N:   base64.RawURLEncoding.EncodeToString([]byte(keyPair.PublicKey.N.Bytes())),
		},
	}
}
