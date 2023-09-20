// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package diagnostics

import (
	"context"

	"google.golang.org/grpc/metadata"
)

type context_key int

const CorrelationIdcontext_key context_key = 0
const CorrelationIdMetadataKey string = "correlation-id-4b54b6c9-647a-4929-be87-481ba63fc04d"

// Replace the context by using this method before making gRPC calls to MOC cloud/node agent, the
// specified correlation-id will also be passed to server.
func NewContextWithCorrelationId(parent context.Context, correlationId string) context.Context {
	ctx := parent
	if ctx == nil {
		ctx = context.Background()
	}

	// Adds to outgoing context
	md, ok := metadata.FromOutgoingContext(ctx)
	if ok {
		md.Set(CorrelationIdMetadataKey, correlationId)
	} else {
		md = metadata.Pairs(CorrelationIdMetadataKey, correlationId)
	}
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Adds to runtime context
	return context.WithValue(ctx, CorrelationIdcontext_key, correlationId)
}

// For server-side MOC agent to pick the correlation-id which is previously set by gRPC client by
// using the NewContextWithCorrelationId function
func GetCorrelationIdFromIncomingContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		values := md.Get(CorrelationIdMetadataKey)
		if len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// Fetch the correlation-id from context, that was either previously set in the current call-stack
// by using the NewContextWithCorrelationId function, or set by the client before making gPRC call.
func GetCorrelationIdFromContext(ctx context.Context) string {
	value, ok := ctx.Value(CorrelationIdcontext_key).(string)
	if ok {
		return value
	}
	return GetCorrelationIdFromIncomingContext(ctx)
}
