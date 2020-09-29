# Script that handles regenerating protobuf files on a dev box.

# Make sure the script exits on first failure and returns the
# proper exit code to the shell.
set -e

# Get script's directory.
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
cd $SCRIPTPATH

# Create directory for build files.
mkdir -p bld

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

# Setup required environment for rpc/gen_proto.sh (called by 'make generate' below).
export GOPATH=$(go env GOPATH)
mkdir -p $GOPATH/src

(
export PATH=$GOPATH/bin:$SCRIPTPATH/bld/protoc/bin:$SCRIPTPATH/bld/protoc/include:$PATH

# Generate the .go files from the .proto files.
make generate
)

# Copy generated .go files into repo.
cp -rf $GOPATH/src/github.com/microsoft/moc/rpc/* rpc/

# Cleanup.
rm -rf $GOPATH/src/github.com/microsoft/moc/
go mod tidy
