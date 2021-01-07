#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the Apache v2.0 license.

# Script that handles regenerating protobuf files.

# Make sure the script exits on first failure and returns the
# proper exit code to the shell.
set -e

while getopts "c" flag
do
    case "${flag}" in
        c) checkGeneratedFiles=1;;
    esac
done

# Get script's directory.
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
cd $SCRIPTPATH

# Create directory for build files.
mkdir -p ./bld/gen

PROTOC_VER=3.11.4
PROTOC_FILE=protoc-$PROTOC_VER-linux-x86_64.zip
PROTOC_FILE_PATH=bld/$PROTOC_FILE

# Check if protoc tool has already been downloaded.
if [ ! -f $PROTOC_FILE_PATH ]; then
    # Download protoc tool.
    (cd bld && curl -OL https://github.com/google/protobuf/releases/download/v$PROTOC_VER/$PROTOC_FILE)
fi

# Unzip protoc tool.
unzip -o $PROTOC_FILE_PATH -d bld/protoc

GOPATH=$(go env GOPATH)

(
export PATH=$GOPATH/bin:$SCRIPTPATH/bld/protoc/bin:$SCRIPTPATH/bld/protoc/include:$PATH

# Generate the .go files from the .proto files.
cd rpc
/bin/bash ./gen_proto.sh
)

# Copy generated .go files into repo.
cp -rf ./bld/gen/github.com/microsoft/moc/rpc/* rpc/

# Cleanup.
rm -rf ./bld/gen/
go mod tidy

if [[ $checkGeneratedFiles ]]; then
    # Check if any files have changed.
    changed=$(git status --short)
    if [[ $changed ]]; then
        # Report warning.
        printf "\n\n##vso[task.logissue type=warning]Generated files are different:\n\n"

        # Log the diff.
        git --no-pager diff
    fi
fi
