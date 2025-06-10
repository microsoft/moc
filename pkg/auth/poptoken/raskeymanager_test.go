package poptoken

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_RsaKeyPairGetKeyPair(t *testing.T) {
	rsamgr, err := NewRsaKeyManager(time.Hour * 1)
	assert.Nil(t, err)

	rsa, err := rsamgr.GetKeyPair()
	assert.Nil(t, err)

	assert.Equal(t, Alg, rsa.Alg)
	assert.Equal(t, Kty, rsa.Kty)
	assert.Equal(t, RsaSize, rsa.RsaSize)
	assert.NotNil(t, rsa.PrivateKey)
	assert.NotNil(t, rsa.PublicKey)

	// now get the keypair a second time, if it has not refreshed, it will be the same value
	rsa2, err := rsamgr.GetKeyPair()
	//validate private key are same
	assert.Equal(t, *rsa.PrivateKey.N, *rsa2.PrivateKey.N)
}

func Test_RsaKeyPairRefresh(t *testing.T) {
	rsamgr, err := NewRsaKeyManager(time.Second * 1)
	assert.Nil(t, err)

	rsa, err := rsamgr.GetKeyPair()
	assert.Nil(t, err)

	time.Sleep(time.Second * 2)

	rsa2, err := rsamgr.GetKeyPair()
	//validate private key are different the second time we ger it
	assert.NotEqual(t, *rsa.PrivateKey.N, *rsa2.PrivateKey.N)
}

func Test_RsaKeyPairForceRefresh(t *testing.T) {
	rsamgr, err := NewRsaKeyManager(time.Hour * 1)
	assert.Nil(t, err)

	rsa, err := rsamgr.GetKeyPair()
	assert.Nil(t, err)

	rsamgr.ForceRefresh()
	// wait for some time for it to respond, note the sleep here is far less than the refesh interval of 1 hour
	time.Sleep(time.Second * 1)

	rsa2, err := rsamgr.GetKeyPair()
	//validate private key are different the second time we ger it
	assert.NotEqual(t, *rsa.PrivateKey.N, *rsa2.PrivateKey.N)
}

// validate keymanager will not deadlock if refresh happen quicker than get call.
func Test_RsaKeyPairNoDeadLock(t *testing.T) {
	rsamgr, err := NewRsaKeyManager(time.Hour * 1)
	assert.Nil(t, err)

	for i := 0; i < 5; i++ {
		rsamgr.ForceRefresh()
		// wait for some time for it to respond
		time.Sleep(time.Second * 1)
	}

	rsa2, err := rsamgr.GetKeyPair()
	assert.Nil(t, err)
	assert.NotNil(t, rsa2.PrivateKey)
}
