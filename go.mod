module github.com/microsoft/moc

go 1.15

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/hectane/go-acl v0.0.0-20190604041725-da78bae5fc95
	github.com/jmespath/go-jmespath v0.3.0
	github.com/kr/pretty v0.1.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.5.1
	golang.org/x/net v0.0.0-20210610132358-84b48f89b13b // indirect
	golang.org/x/sys v0.0.0-20210611083646-a4fc73990273 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/grpc v1.26.0
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.2.8 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c
)

replace (
	github.com/golang/protobuf/protoc-gen-go => github.com/golang/protobuf/protoc-gen-go v1.3.2
	google.golang.org/grpc => google.golang.org/grpc v1.26.0
)
