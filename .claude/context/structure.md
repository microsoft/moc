# Structure

> Last updated: 2026-01-11

## Directory Layout

```
moc/
├── .github/                    # GitHub workflows and templates
├── .gdn/                       # Guardian security config
├── .pipelines/                 # Azure DevOps pipeline definitions
│
├── common/                     # Shared constants and definitions
│
├── pkg/                        # Go utility packages
│   ├── auth/                   # Authentication & authorization
│   │   ├── auth.go             # Authorizer interface, BearerAuthorizer
│   │   ├── auth_env.go         # Environment-based auth settings
│   │   ├── certrenew.go        # Certificate renewal logic
│   │   ├── mock/               # Generated mocks
│   │   └── *_test.go
│   ├── certs/                  # Certificate utilities
│   │   ├── certificateAuthority.go
│   │   ├── cert_utils.go
│   │   └── mock/
│   ├── config/                 # Config file handling
│   ├── convert/                # Type conversions
│   ├── diagnostics/            # Diagnostic context
│   ├── errors/                 # Error handling
│   │   ├── errors.go           # MocError, error type checks
│   │   └── codes/              # MocCode definitions
│   ├── fs/                     # Filesystem utilities (platform-specific)
│   │   ├── fs_darwin.go
│   │   ├── fs_linux.go
│   │   └── fs_windows.go
│   ├── intercept/              # gRPC interceptors
│   ├── logging/                # Logging utilities
│   ├── marshal/                # JSON/Base64 marshaling
│   ├── net/                    # Network utilities
│   ├── path/                   # Path utilities
│   ├── providerid/             # Provider ID parsing
│   ├── redact/                 # Sensitive data redaction
│   ├── status/                 # Status conversions
│   ├── tags/                   # Resource tagging
│   └── validations/            # Input validation
│
├── rpc/                        # Protocol Buffer definitions
│   ├── gen_proto.sh            # Proto generation script
│   │
│   ├── common/                 # Shared proto types
│   │   ├── moc_common_common.proto
│   │   ├── moc_common_computecommon.proto
│   │   ├── moc_common_networkcommon.proto
│   │   └── admin/              # Admin common types
│   │
│   ├── cloudagent/             # Cloud agent definitions
│   │   ├── admin/              # Administrative services
│   │   │   ├── credentialmonitor/
│   │   │   └── logging/
│   │   ├── cloud/              # Cloud resource management
│   │   │   ├── cluster/
│   │   │   ├── controlplane/
│   │   │   ├── etcdcluster/
│   │   │   ├── group/
│   │   │   ├── kubernetes/
│   │   │   ├── location/
│   │   │   ├── node/
│   │   │   ├── subscription/
│   │   │   └── zone/
│   │   ├── compute/            # Compute resources
│   │   │   ├── availabilityset/
│   │   │   ├── baremetalhost/
│   │   │   ├── baremetalmachine/
│   │   │   ├── galleryimage/
│   │   │   ├── placementgroup/
│   │   │   ├── virtualmachine/
│   │   │   ├── virtualmachineimage/
│   │   │   └── virtualmachinescaleset/
│   │   ├── network/            # Network resources
│   │   │   ├── loadbalancer/
│   │   │   ├── logicalnetwork/
│   │   │   ├── macpool/
│   │   │   ├── networkinterface/
│   │   │   ├── networksecuritygroup/
│   │   │   ├── publicipaddress/
│   │   │   ├── vippool/
│   │   │   └── virtualnetwork/
│   │   ├── security/           # Security resources
│   │   │   ├── authentication/
│   │   │   ├── certificate/
│   │   │   ├── identity/
│   │   │   ├── key/
│   │   │   ├── keyvault/
│   │   │   ├── role/
│   │   │   ├── roleassignment/
│   │   │   └── secret/
│   │   └── storage/            # Storage resources
│   │       ├── container/
│   │       ├── virtualharddisk/
│   │       └── virtualmachineimage/
│   │
│   ├── nodeagent/              # Node agent definitions
│   │   ├── admin/
│   │   ├── compute/
│   │   ├── network/
│   │   ├── security/
│   │   └── storage/
│   │
│   ├── guestagent/             # Guest agent definitions
│   ├── mocguestagent/          # MOC guest agent
│   ├── mochostagent/           # MOC host agent
│   ├── lbagent/                # Load balancer agent
│   ├── ipamagent/              # IP address management agent
│   ├── baremetalhostagent/     # Bare metal host agent
│   └── testagent/              # Test agent definitions
│
├── Makefile                    # Build automation
├── gen.sh                      # Proto generation entry point
├── go.mod                      # Go module definition
├── go.sum                      # Dependency checksums
├── azure-pipelines.yml         # CI/CD pipeline
├── README.md                   # Project readme
├── LICENSE                     # Apache 2.0 license
└── SECURITY.md                 # Security policy
```

## Key Files

| File | Purpose |
|------|---------|
| `go.mod` | Go module definition (`github.com/microsoft/moc`) |
| `Makefile` | Build targets: `format`, `test`, `generate`, `mocks` |
| `gen.sh` | Downloads protoc, generates Go code from protos |
| `rpc/gen_proto.sh` | Detailed proto compilation script |
| `.golangci.yml` | Linter configuration |

## Module Relationships

```
rpc/common/           ◄──────── All other rpc/* packages import common types
     │
     ├── cloudagent/compute  ─── Uses Status, Operation, ProvisionState
     ├── cloudagent/network  ─── Uses Tags, Entity
     ├── nodeagent/*         ─── Uses same common types
     └── ...

pkg/errors/           ◄──────── Used by pkg/auth, pkg/status
     │
     └── codes/               ─── MocCode definitions

pkg/auth/             ◄──────── Uses pkg/config, pkg/marshal, rpc/common
pkg/certs/            ◄──────── Certificate management
pkg/config/           ◄──────── Used by pkg/auth for YAML config
pkg/marshal/          ◄──────── Used by pkg/auth for Base64
```

## Generated Files

After running `make generate`:
- `rpc/**/*.pb.go` - Generated from `.proto` files
- `pkg/*/mock/*.go` - Generated by `mockgen`
