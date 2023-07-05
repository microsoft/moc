module github.com/microsoft/moc

go 1.16

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/protobuf v1.5.3
	github.com/hectane/go-acl v0.0.0-20190604041725-da78bae5fc95
	github.com/jmespath/go-jmespath v0.3.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.1
	google.golang.org/grpc v1.26.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/mock v1.6.0
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.11.0 // indirect
	google.golang.org/genproto v0.0.0-20200128133413-58ce757ed39b // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)

replace (
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2
	github.com/golang/mock => github.com/golang/mock v1.6.0
	github.com/golang/protobuf/protoc-gen-go => github.com/golang/protobuf/protoc-gen-go v1.3.2
	golang.org/x/net => golang.org/x/net v0.0.0-20220822230855-b0a4917ee28c
	golang.org/x/sys => golang.org/x/sys v0.0.0-20220823224334-20c2bfdbfe24
)
