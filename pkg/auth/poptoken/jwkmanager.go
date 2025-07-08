package poptoken

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

const (
	IssuerPostfix      = "common/discovery/keys"
	RefreshJwkInterval = time.Hour * 24
)

// Wrapper around jwk library to retrieve and refresh the jwk endpoints from Entra/AAD
type jwkManager struct {
	// STS JWK endpoint, e.g. "https://login.microsoftonline.com/common/discovery/keys"
	jwkEndpoint string
	ar          *jwk.AutoRefresh
}

type JwkInterface interface {
	GetPublicKey(kid string) (*rsa.PublicKey, error)
}

func (j *jwkManager) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	ctx := context.Background()
	keys, err := j.ar.Fetch(ctx, j.jwkEndpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to look up jwk endpoint %s to retrieve keys", j.jwkEndpoint)
	}

	key, ok := keys.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("failed to find kid %s in jwk endpoint %s", kid, j.jwkEndpoint)
	}

	var pKey rsa.PublicKey
	if err := key.Raw(&pKey); err != nil {
		return nil, err
	}

	return &pKey, nil
}

func NewJwkManager(authorityUrl string, refreshInterval time.Duration) (*jwkManager, error) {
	jwkEndpoint := appendUrl(authorityUrl, IssuerPostfix)
	ctx, _ := context.WithCancel(context.Background())
	ar := jwk.NewAutoRefresh(ctx)
	ar.Configure(jwkEndpoint, jwk.WithMinRefreshInterval(refreshInterval))
	_, err := ar.Refresh(ctx, jwkEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh the jwk endpoint %s", jwkEndpoint)
	}

	return &jwkManager{jwkEndpoint: jwkEndpoint, ar: ar}, nil
}
