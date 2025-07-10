module github.com/microsoft/moc

go 1.23.0

require (
	github.com/go-logr/logr v1.4.2
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.4
	github.com/hectane/go-acl v0.0.0-20230122075934-ca0b05cb1adb
	github.com/jmespath/go-jmespath v0.4.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.10.0
	go.uber.org/multierr v1.11.0
	google.golang.org/grpc v1.64.0
	google.golang.org/grpc/security/advancedtls v1.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/grpc/examples v0.0.0-20230224211313-3775f633ce20 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace (
	github.com/golang/mock => github.com/golang/mock v1.6.0
	github.com/stretchr/testify => github.com/stretchr/testify v1.8.3
	go.opentelemetry.io/proto/otlp => go.opentelemetry.io/proto/otlp v0.19.0
	golang.org/x/crypto => golang.org/x/crypto v0.32.0
	golang.org/x/image => golang.org/x/image v0.10.0
	golang.org/x/sys => golang.org/x/sys v0.0.0-20220823224334-20c2bfdbfe24
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.8
)

// Brought in by google.golang.org/grpc bump to 1.56.3, but uses CC-BY-SA-3.0 copyleft license
exclude github.com/ajstarks/deck/generate v0.0.0-20210309230005-c3f852c02e19
