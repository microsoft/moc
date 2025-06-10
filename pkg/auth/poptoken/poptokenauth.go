package poptoken

import (
	"context"

	"github.com/microsoft/moc/pkg/errors"
)

/*
The setup of the pop token creaton is as follows:
	PopTokenAuth (interface betwen grpc and msalauthprovider)
	|
	--> MsalAuthProvider (global component that request the token from Entra/AzureAAD via MSAL SDK)
	    |
		--> NodeAgentPopTokenAuthScheme (implements callback MSAL requires to generate the pop token)
		    |
			--> ShrPopToken (does most of the heavy lifing in generating the pop token)
*/

// This component integrates the MSAL provider to the grpc credentials.PerRPCCredentials interface
type PopTokenAuth struct {
	msalauthprovider *MsalAuthProvider
	targetResourceId string
}

func NewPopTokenAuth(msalProvider *MsalAuthProvider, targetResourceId string) (*PopTokenAuth, error) {
	return &PopTokenAuth{
		msalauthprovider: msalProvider,
		targetResourceId: targetResourceId,
	}, nil
}

func (p *PopTokenAuth) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	accessToken, err := p.msalauthprovider.GetToken(p.targetResourceId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate poptoken")
	}

	return map[string]string{"authorization": accessToken}, nil
}

func (p *PopTokenAuth) RequireTransportSecurity() bool {
	return true
}
