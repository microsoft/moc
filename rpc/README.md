# Generating ProtoBuf

Here you will learn how to generate Proto buffers for the node agent

## Prerequisites

### protoc-gen-go

The simplest way to install protoc-gen-go is to run

`go get -u github.com/golang/protobuf/protoc-gen-go`

The compiler plugin, protoc-gen-go, will be installed in `$GOPATH/bin` unless `$GOBIN` is set. It must be in your `$PATH` for the protocol compiler, protoc, to find it.

## additional steps for building

If when calling protoc you get "File not found" errors on resolving imports

`go get github.com/protocolbuffers/protobuf`

Will download the source for protobuf and it should resolve the problems

## Running gen_proto.sh

Note: make sure you use GOOS="linux" when you get the protoc-gen-go tool, otherwise the Windows version will be downloaded and it will be incompatible with our gen scripts.

`chmod +x ./gen_proto.sh`
`./gen_proto.sh`

You should now see some `*.pb.go` files in the directory


