package poptoken

import (
	"context"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/pkg/errors"
)

// Msal client to generate the pop token. Note that the msal sdk does not provide pop token support
// out of the box, refer to  NodeAgentPopTokenScheme.
type MsalAuthProvider struct {
	clientId       string
	tenantId       string
	authorityUrl   string
	scope          []string
	clientCertPath string
	rsaKeyManager  *RsaKeyManager
}

func (m MsalAuthProvider) refreshConfidentialClient() (*confidential.Client, error) {
	pemData, err := os.ReadFile(m.clientCertPath)
	if err != nil {
		return nil, err
	}

	cert, privateKey, err := confidential.CertFromPEM(pemData, "")
	if err != nil {
		return nil, err
	}

	// the PEM file can contain multiple intermediate certificates to validate TLS cert chaining but we are only interested in our
	// own certificate which is always the first one. See https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2
	cert = cert[:1]
	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create confidential credential from certificate")
	}

	// use Subject NAame and Issuer (SN+I) authentication to request for token. For this to work, Withx5c() must be set
	// to pass the certificate chain in the request header.
	confidentialClient, err := confidential.New(m.authorityUrl, m.clientId, cred, confidential.WithX5C())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create confidential client")
	}

	return &confidentialClient, nil
}

func (m MsalAuthProvider) GetToken(targetResourceId string) (string, error) {

	// TODO: the underlying client certificate will be refreshed, hence we need to also pick up the new certificate
	// Longer run we can cache the client but for now we will refresh the client for every token call.
	confidentialClient, err := m.refreshConfidentialClient()
	if err != nil {
		return "", err
	}

	keyPair, err := m.rsaKeyManager.GetKeyPair()
	if err != nil {
		return "", errors.Wrapf(err, "failed to get keypair for pop token")
	}

	popTokenScheme, err := NewNodeAgentPopTokenAuthScheme(targetResourceId, keyPair)
	if err != nil {
		return "", errors.Wrapf(err, "failed to create new pop token scheme")
	}

	result, err := confidentialClient.AcquireTokenByCredential(context.Background(), m.scope, confidential.WithAuthenticationScheme(popTokenScheme))
	if err != nil {
		return "", errors.Wrapf(err, "failed to get token")
	}
	return result.AccessToken, nil
}

func NewMsalClient(clientId string, tenantId, authorityUrl string, clientCertPath string, rsaKeyManager *RsaKeyManager) (*MsalAuthProvider, error) {
	m := &MsalAuthProvider{
		clientId:       clientId,
		tenantId:       tenantId,
		authorityUrl:   appendUrl(authorityUrl, tenantId),
		clientCertPath: clientCertPath,
		scope:          []string{appendUrl(clientId, ".default")}, // intentionally target itself as the pop token custom claim will contain the actual audience.
		rsaKeyManager:  rsaKeyManager,
	}

	// sanity check to ensure client is setup correctly
	_, err := m.refreshConfidentialClient()
	if err != nil {
		return nil, err
	}

	return m, nil
}
