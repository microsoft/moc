package poptoken

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// This test suite focus on the testing the custom claims of nodeagentpoptokenscheme is returned
// poptokenscheme_test the underlying poptokenscheme_test
func Test_NodeAgentPopTokenScheme(t *testing.T) {
	expectedNodeId := "mynodeId"
	expectedGrpcObjectId := "myObjectId"

	kmgr, err := NewRsaKeyManager(time.Hour)
	assert.Nil(t, err)

	keypair, err := kmgr.GetKeyPair(time.Now())
	assert.Nil(t, err)

	// Generate nodeagent scheme
	nodeAgentScheme, err := NewNodeAgentPopTokenAuthScheme(expectedNodeId, expectedGrpcObjectId, keypair)

	//For nodeagentpoptokenscheme, we just verify that the custom claims were added to the token.
	popToken, err := nodeAgentScheme.FormatAccessToken("accessToken")
	assert.Nil(t, err)
	assert.NotEmpty(t, popToken)

	toks := strings.Split(popToken, ".")
	assert.Equal(t, 3, len(toks))

	body, err := decodeFromBase64[NodeAgentPopTokenBody](toks[1])

	assert.Nil(t, err)
	assert.Equal(t, expectedNodeId, body.NodeId)
	assert.Equal(t, expectedGrpcObjectId, body.GrpcObjectId)
	assert.NotEmpty(t, body.Nonce)

}
