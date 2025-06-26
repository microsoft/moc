package poptoken

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"time"
)

type RsaKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	RsaSize    int
	Kty        string
	Alg        string
}

// a RSA Key generator that refresh the RSA KeyPair at regular interval
// Used to ensure the keys use to sign the poptoken are rotated
type rsaKeyManager struct {
	refreshInterval time.Duration
	createdDateTime time.Time
	privateKey      *rsa.PrivateKey
	mutex           sync.Mutex
}

const (
	DefaultRefreshInterval = time.Hour * 8
	RsaSize                = 2048
	Kty                    = "RSA"
	Alg                    = "RS256"
)

func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RsaSize)
}

// Return a KeyPair. The keypair is its own copy and not a reference.
func (r *rsaKeyManager) GetKeyPair(now time.Time) (*RsaKeyPair, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.createdDateTime.Add(r.refreshInterval).Before(now) {
		newPKey, err := generatePrivateKey()
		if err != nil {
			return nil, err
		}
		r.privateKey = newPKey
		r.createdDateTime = now
	}

	// Create and return a deep copy of the private key so clients are not impacted by a rotation midway.
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(r.privateKey)
	privateKeyCopy, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return &RsaKeyPair{
		PrivateKey: privateKeyCopy,
		PublicKey:  privateKeyCopy.Public().(*rsa.PublicKey),
		RsaSize:    RsaSize,
		Kty:        Kty,
		Alg:        Alg,
	}, nil
}

// Create a new RSAKeyManager that will refresh the keypair in the background.
func NewRsaKeyManager(refreshInterval time.Duration) (*rsaKeyManager, error) {
	var err error
	rsaMgr := &rsaKeyManager{}

	rsaMgr.refreshInterval = refreshInterval
	rsaMgr.privateKey, err = generatePrivateKey()
	if err != nil {
		return nil, err
	}
	return rsaMgr, nil
}
