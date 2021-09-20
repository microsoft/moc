# Copyright (c) Microsoft Corporation.
# Licensed under the Apache v2.0 license.
GOCMD=GO111MODULE=on GOARCH=amd64 go
GOBUILD=$(GOCMD) build -v #-mod=vendor
GOTEST=$(GOCMD) test -v 
GOHOSTOS=$(strip $(shell $(GOCMD) env get GOHOSTOS))

# Private repo workaround
export GOPRIVATE = github.com/microsoft
# Active module mode, as we use go modules to manage dependencies
export GO111MODULE=on

#
PKG := 

all: format test unittest

.PHONY: vendor
vendor:
	go mod tidy

format:
	gofmt -s -w rpc/ pkg/ 

test:
	GOOS=windows go build ./...

unittest:
	$(GOTEST) ./pkg/marshal
	$(GOTEST) ./pkg/config
	$(GOTEST) ./pkg/tags
	$(GOTEST) ./pkg/net
	$(GOTEST) ./pkg/certs
	$(GOTEST) ./pkg/auth

generate:
	(./gen.sh)

pipeline:
	(./gen.sh -c)