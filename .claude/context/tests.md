# Tests

> Last updated: 2026-01-11

## Test Framework

- **Standard Go testing** (`testing` package)
- **Testify** for assertions (`github.com/stretchr/testify`)
- **Mockgen** for generating mocks (`github.com/golang/mock`)

## Running Tests

### All Tests

```bash
make test
# or
make unittest
# or directly
go test -v ./pkg/...
```

### Specific Package

```bash
go test -v ./pkg/auth/...
go test -v ./pkg/errors/...
```

### With Coverage

```bash
go test -v -cover ./pkg/...
```

## Test Organization

Tests are colocated with implementation files:

```
pkg/
├── auth/
│   ├── auth.go
│   ├── auth_test.go        # Tests for auth.go
│   ├── auth_env.go
│   ├── auth_env_test.go    # Tests for auth_env.go
│   ├── certrenew.go
│   └── certrenew_test.go
├── errors/
│   ├── errors.go
│   ├── errors_test.go
│   └── codes/
│       ├── codes.go
│       └── codes_test.go
└── ...
```

## Test Files

| File | Coverage |
|------|----------|
| `pkg/auth/auth_test.go` | Authorizer, credentials |
| `pkg/auth/auth_env_test.go` | Environment settings |
| `pkg/auth/certrenew_test.go` | Certificate renewal |
| `pkg/certs/certs_test.go` | Certificate utilities |
| `pkg/config/config_test.go` | Config loading |
| `pkg/errors/errors_test.go` | Error handling, type checks |
| `pkg/errors/codes/codes_test.go` | MocCode operations |
| `pkg/logging/logger_test.go` | Logging utilities |
| `pkg/marshal/marshal_test.go` | JSON/Base64 marshaling |
| `pkg/net/net_test.go` | Network utilities |
| `pkg/redact/redact_test.go` | Sensitive data redaction |
| `pkg/status/status_test.go` | Status conversions |
| `pkg/tags/tags_test.go` | Resource tagging |
| `pkg/validations/proxy_validation_test.go` | Proxy validation |
| `rpc/nodeagent/storage/moc_nodeagent_virtualharddisk_test.go` | VHD proto tests |

## Mock Generation

Mocks are generated using `mockgen`:

```go
// In pkg/auth/auth.go
//go:generate mockgen -destination mock/auth_mock.go github.com/microsoft/moc/pkg/auth Authorizer
```

Generate all mocks:

```bash
make mocks
```

This runs:
```bash
go mod download github.com/golang/mock
go get github.com/golang/mock@v1.6.0
go generate ./...
```

## Writing New Tests

### Basic Test Structure

```go
package auth

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestNewBearerAuthorizer(t *testing.T) {
    // Arrange
    tp := NewEmptyTokenCredentialProvider()
    tc := NewEmptyTransportCredential().GetTransportCredentials()

    // Act
    auth := NewBearerAuthorizer(tp, tc)

    // Assert
    assert.NotNil(t, auth)
    assert.NotNil(t, auth.WithRPCAuthorization())
    assert.NotNil(t, auth.WithTransportAuthorization())
}
```

### Using Mocks

```go
package somepackage

import (
    "testing"
    "github.com/golang/mock/gomock"
    "github.com/microsoft/moc/pkg/auth/mock"
)

func TestWithMock(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()

    mockAuth := mock.NewMockAuthorizer(ctrl)
    mockAuth.EXPECT().WithRPCAuthorization().Return(nil)

    // Use mockAuth...
}
```

### Error Testing Pattern

```go
func TestIsNotFound(t *testing.T) {
    tests := []struct {
        name     string
        err      error
        expected bool
    }{
        {"nil error", nil, false},
        {"not found error", errors.NotFound, true},
        {"wrapped not found", errors.Wrap(errors.NotFound, "msg"), true},
        {"different error", errors.AlreadyExists, false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := errors.IsNotFound(tt.err)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

## CI Integration

Tests run in Azure Pipelines via:

```bash
make test
```

The `unittest` target executes:
```bash
GO111MODULE=on GOARCH=amd64 go test -v ./pkg/...
```
