// Package intercept provides gRPC interceptors for MOCStack clients.
package intercept

import (
	"context"

	"github.com/microsoft/moc/pkg/errors"
	"google.golang.org/grpc"
)

// NewErrorParsingInterceptor transforms grpc errors to moc errors
func NewErrorParsingInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoker(ctx, method, req, reply, cc, opts...)
		return errors.ParseGRPCError(err)
	}
}
