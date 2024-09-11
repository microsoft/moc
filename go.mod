module github.com/microsoft/moc

go 1.22

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.4
	github.com/hectane/go-acl v0.0.0-20230122075934-ca0b05cb1adb
	github.com/jmespath/go-jmespath v0.4.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.3
	google.golang.org/grpc v1.59.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240624140628-dc46fd24d27d // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace (
	github.com/golang/mock => github.com/golang/mock v1.6.0
	github.com/stretchr/testify => github.com/stretchr/testify v1.8.3
	go.opentelemetry.io/proto/otlp => go.opentelemetry.io/proto/otlp v0.19.0
	golang.org/x/crypto => golang.org/x/crypto v0.17.0
	golang.org/x/image => golang.org/x/image v0.10.0
	golang.org/x/sys => golang.org/x/sys v0.0.0-20220823224334-20c2bfdbfe24
	google.golang.org/grpc => google.golang.org/grpc v1.59.0
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.8
)

// Brought in by google.golang.org/grpc bump to 1.56.3, but uses CC-BY-SA-3.0 copyleft license
exclude github.com/ajstarks/deck/generate v0.0.0-20210309230005-c3f852c02e19
