# Architecture

> Last updated: 2026-01-11

## System Overview

**MOC (Microsoft On-premises Cloud)** is a Go library that provides Protocol Buffer (protobuf) definitions and shared utilities for Microsoft's on-premises cloud infrastructure. It serves as the core API contract layer between various cloud agents and services.

## System Type

This is a **shared library/SDK** that provides:
- gRPC service definitions via Protocol Buffers
- Common utility packages for authentication, error handling, logging, etc.
- Generated Go code from `.proto` files

## Core Components

### 1. RPC Definitions (`rpc/`)

The heart of the repository - protobuf definitions for multiple agent types:

| Agent | Purpose |
|-------|---------|
| `cloudagent` | Primary cloud management - compute, network, storage, security, admin |
| `nodeagent` | Node-level operations - VM management, storage, networking on hosts |
| `guestagent` | Guest OS operations within VMs |
| `mocguestagent` | MOC-specific guest agent operations |
| `mochostagent` | Host-level MOC operations |
| `lbagent` | Load balancer management |
| `ipamagent` | IP address management |
| `baremetalhostagent` | Bare metal host operations |
| `testagent` | Testing agent definitions |

### 2. Utility Packages (`pkg/`)

Reusable Go packages:

| Package | Responsibility |
|---------|---------------|
| `auth` | Authentication, authorization, TLS credentials, JWT tokens |
| `certs` | Certificate authority, certificate utilities |
| `config` | Configuration file handling (YAML/JSON) |
| `errors` | Custom error types with MOC error codes, gRPC error handling |
| `logging` | Structured logging utilities |
| `marshal` | JSON/Base64 marshaling utilities |
| `net` | Network utilities |
| `status` | Status conversion utilities |
| `tags` | Resource tagging utilities |
| `validations` | Input validation helpers |

### 3. Common Proto Definitions (`rpc/common/`)

Shared protobuf types used across all agents:
- `moc_common_common.proto` - Core enums (Operation, ProvisionState, HealthState, etc.)
- `moc_common_computecommon.proto` - Compute-related shared types
- `moc_common_networkcommon.proto` - Network-related shared types

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Applications                      │
│           (moc-sdk-for-go, Azure Arc, etc.)                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ gRPC calls (using generated stubs)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    This Repository (moc)                     │
│   ┌─────────────────┐  ┌─────────────────┐                  │
│   │  .proto files   │  │  pkg/ utilities │                  │
│   │  (contracts)    │  │  (auth, errors) │                  │
│   └────────┬────────┘  └────────┬────────┘                  │
│            │                    │                            │
│            ▼                    ▼                            │
│   ┌─────────────────────────────────────────────┐           │
│   │        Generated Go code (*.pb.go)          │           │
│   └─────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Imported as dependency
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    MOC Agent Implementations                 │
│    (cloudagent-exe, nodeagent-exe, etc. in other repos)     │
└─────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

1. **Protocol Buffers for API Contracts**: All service interfaces defined in `.proto` files ensure language-agnostic contracts and efficient serialization.

2. **Agent-based Architecture**: Separate agents for different responsibilities (cloud, node, guest, etc.) enabling distributed deployment.

3. **Shared Common Types**: Central `rpc/common/` prevents duplication and ensures consistency across agents.

4. **MOC Error Codes**: Custom error code system (`pkg/errors/codes/`) for precise error classification across the stack.

5. **Certificate-based Authentication**: TLS with client certificates for secure agent-to-agent communication (`pkg/auth/`).

## External Dependencies

- `google.golang.org/grpc` - gRPC framework
- `google.golang.org/protobuf` - Protocol Buffers
- `github.com/golang-jwt/jwt/v4` - JWT token handling
- `github.com/pkg/errors` - Error wrapping
- `go.uber.org/multierr` - Multiple error aggregation
