package poptoken

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// This test suite focus on the testing nodeagentpoptokenscheme is returning the expected values that MSAL expected
// the actual token generation is tested in shrpoptoken_test
func Test_NodeAgentPopTokenScheme(t *testing.T) {
	expectedResourceId := "myresourceId"

	kmgr, err := NewRsaKeyManager(time.Hour)
	assert.Nil(t, err)

	keypair, err := kmgr.GetKeyPair()
	assert.Nil(t, err)

	// create a "reference" pop token that we can use to validate some of the nodeagentpoptokenscheme content since it
	// should generate the same values
	refPopToken, err := NewPopToken(keypair)
	assert.Nil(t, err)

	// Generate nodeagent scheme
	nodeAgentScheme, err := NewNodeAgentPopTokenAuthScheme(expectedResourceId, keypair)

	//validate AccessTokenType returns "pop"
	assert.Equal(t, TokenType, nodeAgentScheme.AccessTokenType())
	assert.Equal(t, refPopToken.Header.Typ, nodeAgentScheme.AccessTokenType())

	//Validate KeyID
	assert.Equal(t, refPopToken.Header.Kid, nodeAgentScheme.KeyID())

	// Validate TokenRequestParams returns a specific struct
	reqCnf := nodeAgentScheme.TokenRequestParams()

	tokenType, ok := reqCnf["token_type"]
	assert.True(t, ok)
	assert.Equal(t, refPopToken.Header.Typ, tokenType)

	expectedCnf, err := refPopToken.GetReqCnf()
	assert.Nil(t, err)
	cnf, ok := reqCnf["req_cnf"]
	assert.True(t, ok)
	assert.Equal(t, expectedCnf, cnf)

	// Validate FormatAccessToken. Here we just check that the custom claim "resourceId" was added.
	popToken, err := nodeAgentScheme.FormatAccessToken("accessToken")
	assert.Nil(t, err)
	assert.NotEmpty(t, popToken)

	toks := strings.Split(popToken, ".")
	assert.Equal(t, 3, len(toks))
	body, err := decodeFromBase64[nodeAgentPopTokenBody](toks[1])
	assert.Nil(t, err)
	assert.Equal(t, expectedResourceId, body.ResourceId)

}
