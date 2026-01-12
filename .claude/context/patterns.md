# Patterns

> Last updated: 2026-01-11

## Design Patterns

### 1. Request/Response Pattern (gRPC)

All services follow a consistent request/response pattern:

```protobuf
// From rpc/cloudagent/compute/virtualmachine/moc_cloudagent_virtualmachine.proto
message VirtualMachineRequest {
    repeated VirtualMachine VirtualMachines = 1;
    Operation OperationType = 2;
}

message VirtualMachineResponse {
    repeated VirtualMachine VirtualMachines = 1;
    google.protobuf.BoolValue Result = 2;
    string Error = 3;
}

service VirtualMachineAgent {
    rpc Invoke(VirtualMachineRequest) returns (VirtualMachineResponse) {}
}
```

**Pattern**: Resource + "Request"/"Response" suffix, with `Invoke` as the standard CRUD method.

### 2. Operation-based CRUD

Instead of separate Create/Read/Update/Delete methods, operations are indicated via enum:

```protobuf
// From rpc/common/moc_common_common.proto
enum Operation {
    GET = 0;
    POST = 1;
    DELETE = 2;
    UPDATE = 3;
    IMPORT = 4;
    EXPORT = 5;
    VALIDATE = 6;
    // ...
}
```

### 3. Status Pattern

Resources share a common status structure:

```protobuf
message Status {
    Health health = 1;
    ProvisionStatus provisioningStatus = 2;
    Error lastError = 3;
    Version version = 4;
    // ...
}
```

### 4. Authorizer Interface

Authentication follows an interface-based pattern:

```go
// From pkg/auth/auth.go
type Authorizer interface {
    WithTransportAuthorization() credentials.TransportCredentials
    WithRPCAuthorization() credentials.PerRPCCredentials
}
```

Implementation example:
```go
type BearerAuthorizer struct {
    tokenProvider        JwtTokenProvider
    transportCredentials credentials.TransportCredentials
}
```

### 5. MOC Error System

Custom error codes with type checking:

```go
// From pkg/errors/errors.go
type MocError struct {
    code moccodes.MocCode
    err  string
}

// Predefined errors
var NotFound error = NewMocError(moccodes.NotFound)
var AlreadyExists error = NewMocError(moccodes.AlreadyExists)

// Type checking functions
func IsNotFound(err error) bool {
    return checkError(err, NotFound)
}
```

### 6. Mock Generation

Uses `mockgen` for test doubles:

```go
// From pkg/auth/auth.go
//go:generate mockgen -destination mock/auth_mock.go github.com/microsoft/moc/pkg/auth Authorizer
```

## Code Organization

### Proto File Naming
- Pattern: `moc_{agent}_{resource}.proto`
- Examples:
  - `moc_cloudagent_virtualmachine.proto`
  - `moc_nodeagent_virtualharddisk.proto`
  - `moc_common_common.proto`

### Package Structure
- Generated code maintains same directory structure as `.proto` files
- Package names: `moc.{agent}.{domain}` (e.g., `moc.cloudagent.compute`)

### Go Package Layout
```
pkg/
├── auth/          # Authentication/authorization
│   ├── auth.go    # Main implementation
│   ├── mock/      # Generated mocks
│   └── *_test.go  # Tests
├── errors/
│   ├── errors.go
│   └── codes/     # Error code definitions
└── ...
```

## Naming Conventions

### Proto
- Messages: PascalCase (`VirtualMachine`, `StorageConfiguration`)
- Fields: camelCase (`diskname`, `networkInterfaceName`)
- Enums: SCREAMING_SNAKE_CASE (`CREATE_FAILED`, `PROVISION_FAILED`)
- Services: PascalCase + "Agent" suffix (`VirtualMachineAgent`)

### Go
- Exported functions: PascalCase (`NewBearerAuthorizer`)
- Unexported: camelCase (`checkError`)
- Constants: PascalCase for exported, camelCase for unexported
- Errors: PascalCase variables (`NotFound`, `AlreadyExists`)

## Error Handling

### Proto to Go Error Conversion
```go
// Convert error to protobuf
func ErrorToProto(err error) *common.Error {
    return &common.Error{
        Code:    GetMocErrorCode(err).ToUint32(),
        Message: err.Error(),
    }
}

// Convert protobuf to error
func ProtoToMocError(protoErr *common.Error) error {
    return &MocError{
        code: moccodes.Convert(protoErr.GetCode()),
        err:  protoErr.Message,
    }
}
```

### gRPC Error Wrapping
```go
func GetGRPCError(err error) error {
    var st *status.Status
    switch {
    case IsNotFound(err):
        st = status.New(codes.NotFound, err.Error())
    case IsAlreadyExists(err):
        st = status.New(codes.AlreadyExists, err.Error())
    default:
        st = status.New(codes.Unknown, err.Error())
    }
    st, _ = st.WithDetails(ErrorToProto(err))
    return st.Err()
}
```

## Async Patterns

No explicit async patterns in this library - it provides synchronous gRPC service definitions. Async handling is implemented by consumers.

## Sensitive Data Handling

Proto fields marked with custom option for redaction:

```protobuf
extend google.protobuf.FieldOptions {
    bool sensitive = 50001;
}

message SSHPublicKey {
    string keydata = 1 [(sensitive) = true];
}
```
