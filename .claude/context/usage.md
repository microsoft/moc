# Usage

> Last updated: 2026-01-11

## Prerequisites

- **Go 1.24+** (specified in `go.mod`)
- **protoc** (Protocol Buffer compiler) - automatically downloaded by `gen.sh`
- **Linux environment** for proto generation (uses `protoc-linux-x86_64`)

## Installation

### As a Dependency

Add to your Go project:

```bash
go get github.com/microsoft/moc
```

Import packages:

```go
import (
    "github.com/microsoft/moc/pkg/auth"
    "github.com/microsoft/moc/pkg/errors"
    "github.com/microsoft/moc/rpc/cloudagent/compute"
)
```

### For Development

```bash
git clone https://github.com/microsoft/moc.git
cd moc
```

## Common Commands

### Generate Proto Files

Regenerate all `.pb.go` files from `.proto` definitions:

```bash
make generate
```

This will:
1. Download `protoc` (if not present)
2. Install `protoc-gen-go`
3. Run `gen.sh` to compile all protos
4. Copy generated files to `rpc/` directories

### Build and Format

```bash
make all        # Format + test
make format     # Run gofmt on rpc/ and pkg/
make tidy       # Run go mod tidy
```

### Run Tests

```bash
make test       # Run all unit tests
make unittest   # Same as test
```

### Generate Mocks

```bash
make install-mockgen  # Install mockgen if not present
make mocks            # Generate mock files
```

### Lint

```bash
make golangci-lint    # Run golangci-lint
```

## Configuration

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `GOPRIVATE` | Set to `github.com/microsoft` for private module access |
| `GO111MODULE` | Set to `on` (required) |

### Authentication Setup

The `pkg/auth` package reads from standard locations:

```go
// Get authorizer from environment
auth, err := auth.NewAuthorizerFromEnvironment("serverName")

// Or from specific file
auth, err := auth.NewAuthorizerFromEnvironmentByName("serverName", "subfolder", "filename")
```

Default config locations (platform-specific, see `pkg/auth/auth_env.go`).

## Development Workflow

### Adding a New Proto Definition

1. Create `.proto` file in appropriate `rpc/` subdirectory
2. Follow naming convention: `moc_{agent}_{resource}.proto`
3. Import common types:
   ```protobuf
   import "moc_common_common.proto";
   ```
4. Run `make generate`
5. Commit both `.proto` and generated `.pb.go` files

### Adding a New Utility Package

1. Create directory under `pkg/`
2. Add implementation with `_test.go` files
3. If interface needed for testing, add `//go:generate mockgen` directive
4. Run `make mocks` if using mock generation

### Modifying Error Codes

1. Add new code to `pkg/errors/codes/codes.go`
2. Run `go generate ./pkg/errors/codes/...` to update string methods
3. Add corresponding error variable and check function in `pkg/errors/errors.go`

## CI/CD Pipeline

The repository uses Azure Pipelines (`azure-pipelines.yml`) with:

```bash
make pipeline   # Used in CI - runs gen.sh with -c flag to check for diffs
```

The `-c` flag causes `gen.sh` to warn if generated files differ from committed versions.
