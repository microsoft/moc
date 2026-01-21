# Copyright (c) Microsoft Corporation.
# Licensed under the Apache v2.0 license.
GOCMD=GO111MODULE=on GOARCH=amd64 go
GOBUILD=$(GOCMD) build -v #-mod=vendor
GOTEST=$(GOCMD) test -v 
GOHOSTOS=$(strip $(shell $(GOCMD) env get GOHOSTOS))
MOCKGEN=$(shell command -v mockgen 2> /dev/null)
GOPATH_BIN := $(shell go env GOPATH)/bin

# Private repo workaround
export GOPRIVATE = github.com/microsoft
# Active module mode, as we use go modules to manage dependencies
export GO111MODULE=on

#
PKG := 

all: tidy format test

.PHONY: tidy
tidy:
	go mod tidy

format:
	gofmt -s -w rpc/ pkg/ 

bootstrap: tidy
	GOOS="linux" go get -u google.golang.org/grpc@v1.59.0
	GOOS="linux" go install github.com/golang/protobuf/protoc-gen-go@v1.3.2

test: unittest

unittest:
	$(GOTEST) ./pkg/...

generate: bootstrap
	(./gen.sh)

pipeline: bootstrap
	(./gen.sh -c)


## Install mockgen golang bin
install-mockgen:
ifeq ($(MOCKGEN),)
	go install github.com/golang/mock/mockgen@v1.6.0
endif
	MOCKGEN=$(shell command -v mockgen 2> /dev/null)

mocks: tidy
	go mod download github.com/golang/mock
	go get github.com/golang/mock@v1.6.0
	go generate ./...


golangci-lint:
	$(GOCMD) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOPATH_BIN)/golangci-lint run --config .golangci.yml
