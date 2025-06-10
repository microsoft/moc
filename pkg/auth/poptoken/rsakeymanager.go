package poptoken

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
type RsaKeyManager struct {
	refreshInterval  time.Duration
	refreshTicker    *time.Ticker
	keyPairChan      chan *rsa.PrivateKey
	forceRefreshChan chan bool
	stopChan         chan bool
	privateKey       *rsa.PrivateKey
}

const (
	RsaSize = 2048
	Kty     = "RSA"
	Alg     = "RS256"
)

func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RsaSize)
}

// Background job to continuously refresh the keypair in a best effort basis.
func (r *RsaKeyManager) refreshPrivateKeyJob() {
	for {
		select {
		case <-r.stopChan:
			return
		case <-r.refreshTicker.C:
			r.tryRefreshPrivateKey()
		case <-r.forceRefreshChan:
			r.tryRefreshPrivateKey()
		}
	}
}

// Generate new keypair and send it back to the main go routine.
func (r *RsaKeyManager) tryRefreshPrivateKey() {
	privateKey, err := generatePrivateKey()
	// generatePrivateKey() should not fail, we don't have a good way to surface this error
	if err == nil {
		// In the unlikely event the refresh rate happens faster than getting the key,
		// drop the key to prevent deadlocking the channel
		select {
		case r.keyPairChan <- privateKey:
		default:
			// imply key is dropped if channel is full.
		}
	}
}

// Return a KeyPair. The keypair is its own copy and not a reference.
func (r *RsaKeyManager) GetKeyPair() (*RsaKeyPair, error) {
	// non blocking wait to get new private key if available
	select {
	case r.privateKey = <-r.keyPairChan:
	default:
		//continue to use existing key
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

// Force a refresh now. This can be use during test.
func (r *RsaKeyManager) ForceRefresh() {
	r.forceRefreshChan <- true
}

// Stop the refresh of the keypair.
func (r *RsaKeyManager) Stop() {
	r.stopChan <- true
}

// Create a new RSAKeyManager that will refresh the keypair in the background.
func NewRsaKeyManager(refreshInterval time.Duration) (*RsaKeyManager, error) {
	var err error
	rsaMgr := &RsaKeyManager{}

	rsaMgr.refreshInterval = refreshInterval
	rsaMgr.refreshTicker = time.NewTicker(rsaMgr.refreshInterval)
	rsaMgr.privateKey, err = generatePrivateKey()
	if err != nil {
		return nil, err
	}
	rsaMgr.forceRefreshChan = make(chan bool)
	rsaMgr.stopChan = make(chan bool)
	rsaMgr.keyPairChan = make(chan *rsa.PrivateKey, 2)

	go rsaMgr.refreshPrivateKeyJob()
	return rsaMgr, nil
}
