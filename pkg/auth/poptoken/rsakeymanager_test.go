package poptoken

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testRsaValidInterval  = time.Hour * 1
	testRsaNowDateTimeStr = "2025-12-01T15:00:00Z" //time.Parse(time.RFC3339, "2025-12-01T15:00:00Z")
)

func Test_RsaKeyManagerGetKeyPair(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, testNonceNowDateTimeStr)
	rsamgr, err := NewRsaKeyManager(testRsaValidInterval)
	assert.Nil(t, err)

	rsa, err := rsamgr.GetKeyPair(now)
	assert.Nil(t, err)

	assert.Equal(t, Alg, rsa.Alg)
	assert.Equal(t, Kty, rsa.Kty)
	assert.Equal(t, RsaSize, rsa.RsaSize)
	assert.NotNil(t, rsa.PrivateKey)
	assert.NotNil(t, rsa.PublicKey)

	// now get the keypair a second time, if it has not refreshed, it will be the same value
	rsa2, err := rsamgr.GetKeyPair(now)
	//validate private key are equal value
	assert.Equal(t, *rsa.PrivateKey.N, *rsa2.PrivateKey.N)
}

func Test_RsaKeyManagerGetKeyPairRotated(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, testNonceNowDateTimeStr)
	rsamgr, err := NewRsaKeyManager(testRsaValidInterval)
	assert.Nil(t, err)

	rsa, err := rsamgr.GetKeyPair(now)
	assert.Nil(t, err)

	// now get the keypair a second time past the refresh interval, a new key should be generated.
	rsa2, err := rsamgr.GetKeyPair(now.Add(testRsaValidInterval * 2))
	assert.Nil(t, err)

	//validate the two keys are now different.
	assert.NotEqual(t, *rsa.PrivateKey.N, *rsa2.PrivateKey.N)
}
