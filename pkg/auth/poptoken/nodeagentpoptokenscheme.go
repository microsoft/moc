package poptoken

import "github.com/google/uuid"

// Implements the interface for MSAL SDK to callback when creating the poptoken.
// See AuthenticationScheme interface in https://github.com/AzureAD/microsoft-authentication-library-for-go/blob/main/apps/internal/oauth/ops/authority/authority.go#L146
type NodeAgentPopTokenAuthScheme struct {
	*PopTokenAuthScheme
}

// Create a new instance of NodeAgentPopTokenAuthScheme.
// targetResourceId: the ARM resourceId representing the edge node machine. This is the Arc For Server resource Id and is part of the node entity.
// grpcObjectId: the uri to the grpc entity, e.g. container. This will be passed in as part of the grpc metadata.
func NewNodeAgentPopTokenAuthScheme(targetNodeId string, grpcObjectId string) (*NodeAgentPopTokenAuthScheme, error) {
	popTokenScheme, err := NewPopTokenAuthScheme(
		map[string]interface{}{
			"nodeid": targetNodeId,
			"p":      grpcObjectId,
			"nonce":  uuid.New().String(),
		})
	if err != nil {
		return nil, err
	}

	return &NodeAgentPopTokenAuthScheme{
		PopTokenAuthScheme: popTokenScheme,
	}, nil
}
