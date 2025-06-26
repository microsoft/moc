package poptoken

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestPopTokenSchemeBody struct {
	ShrPopTokenBody
	NodeId string `json:"nodeid"`
}

// This test suite focus on the testing poptokenscheme is returning the expected values that MSAL expected
// the actual token generation is tested in shrpoptoken_test
func Test_PopTokenScheme(t *testing.T) {
	expectedNodeId := "mynodeId"

	kmgr, err := NewRsaKeyManager(time.Hour)
	assert.Nil(t, err)

	keypair, err := kmgr.GetKeyPair(time.Now())
	assert.Nil(t, err)

	// create a "reference" pop token that we can use to validate some of the nodeagentpoptokenscheme content since it
	// should generate the same values
	refPopToken, err := NewPopToken(keypair)
	assert.Nil(t, err)

	// Generate nodeagent scheme
	claims := map[string]interface{}{
		"nodeId": expectedNodeId,
	}
	popTokenScheme, err := NewPopTokenAuthScheme(claims, keypair)

	//validate AccessTokenType returns "pop"
	assert.Equal(t, TokenType, popTokenScheme.AccessTokenType())
	assert.Equal(t, refPopToken.Header.Typ, popTokenScheme.AccessTokenType())

	//Validate KeyID
	assert.Equal(t, refPopToken.Header.Kid, popTokenScheme.KeyID())

	// Validate TokenRequestParams returns a specific struct
	reqCnf := popTokenScheme.TokenRequestParams()

	tokenType, ok := reqCnf["token_type"]
	assert.True(t, ok)
	assert.Equal(t, refPopToken.Header.Typ, tokenType)

	expectedCnf := refPopToken.GetReqCnf()
	assert.Nil(t, err)
	cnf, ok := reqCnf["req_cnf"]
	assert.True(t, ok)
	assert.Equal(t, expectedCnf, cnf)

	// Validate FormatAccessToken. Here we just check that the custom claim "nodeId" was added.
	popToken, err := popTokenScheme.FormatAccessToken("accessToken")
	assert.Nil(t, err)
	assert.NotEmpty(t, popToken)

	toks := strings.Split(popToken, ".")
	assert.Equal(t, 3, len(toks))
	body, err := decodeFromBase64[TestPopTokenSchemeBody](toks[1])
	assert.Nil(t, err)
	assert.Equal(t, expectedNodeId, body.NodeId)

}
