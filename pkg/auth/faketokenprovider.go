package auth

import (
	"context"
)

type fakeTokenProvider struct {
}

func NewFakeTokenProvier() (*fakeTokenProvider, error) {
	return &fakeTokenProvider{}, nil
}

func (f fakeTokenProvider) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	accessToken := "my fake token"
	return map[string]string{"authorization": accessToken}, nil
}

func (f fakeTokenProvider) RequireTransportSecurity() bool {
	return false
}
