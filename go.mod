module github.com/microsoft/moc

go 1.16

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/protobuf v1.5.3
	github.com/hectane/go-acl v0.0.0-20190604041725-da78bae5fc95
	github.com/jmespath/go-jmespath v0.3.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.3
	golang.org/x/net v0.20.0 // indirect
	google.golang.org/grpc v1.56.3
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/golang/mock v1.6.0
	google.golang.org/protobuf v1.32.0 // indirect
)

replace (
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2
	github.com/golang/mock => github.com/golang/mock v1.6.0
	github.com/golang/protobuf/protoc-gen-go => github.com/golang/protobuf/protoc-gen-go v1.3.2
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20211202192323-5770296d904e
	golang.org/x/sys => golang.org/x/sys v0.0.0-20220823224334-20c2bfdbfe24
	google.golang.org/grpc => google.golang.org/grpc v1.56.3
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.4
)
