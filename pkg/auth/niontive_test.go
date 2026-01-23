package auth

import (
	"fmt"
	"testing"
)

// NIONTIVE - unit test to verify if:
// Cert doesn't need to be renewed and token is expired
// Bubbles up no error for authorizer creation, and we attempt to use an expired token.

func TestNiontive(t *testing.T) {
	serverName := "niontive-test-server"

	t.Setenv("WSSD_CLIENT_TOKEN", "cloud-login.yaml")

	auth, err := NewAuthorizerFromEnvironment(serverName)
	if err != nil {
		t.Error("Expected no error when creating authorizer, got:", err)
	}

	rpcCreds := auth.WithRPCAuthorization()

	fmt.Println("RPC Credentials:", rpcCreds)
}
