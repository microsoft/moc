# Copyright (c) Microsoft Corporation.
# Licensed under the Apache v2.0 license.

# Make sure the script exits on first failure
# and returns the proper exit code to the 
# shell
set -e

#### 
Agent="nodeagent"
echo "Generating Protoc for $Agent"
Module="common"
echo "Generating $Module protoc"
protoc -I common common/common.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I common common/computecommon.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I common common/nodeinfo.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I common common/networkcommon.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I common common/admin/logging/logging.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I common common/admin/health/health.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I common common/admin/recovery/recovery.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I common common/notification.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I common common/security.proto --go_out=plugins=grpc:$GOPATH/src

Module="admin"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/credentialmonitor -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/credentialmonitor/credentialmonitor.proto  --go_out=plugins=grpc:$GOPATH/src

Module="network"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualnetwork -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/virtualnetwork/virtualnetwork.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/loadbalancer -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/loadbalancer/loadbalancer.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/virtualnetworkinterface -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/virtualnetworkinterface/virtualnetworkinterface.proto --go_out=plugins=grpc:$GOPATH/src

# Generate compute agent protoc
Module="compute"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualmachine -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/virtualmachine/virtualmachine.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/virtualmachinescaleset -I $Agent/$Module/virtualmachine -I $GOPATH/src/github.com/protocolbuffers/protobuf/src -I $Agent/network/virtualnetworkinterface -I ./common $Agent/$Module/virtualmachinescaleset/virtualmachinescaleset.proto --go_out=plugins=grpc:$GOPATH/src

Module="storage"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualharddisk -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/virtualharddisk/virtualharddisk.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/container -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/container/container.proto  --go_out=plugins=grpc:$GOPATH/src

Module="security"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/identity -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/identity/identity.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/keyvault/secret -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/keyvault/secret/secret.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/keyvault -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src -I $Agent/$Module/keyvault/secret $Agent/$Module/keyvault/keyvault.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/authentication -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src -I $Agent/$Module/identity $Agent/$Module/authentication/authentication.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/certificate -I ./common -I $Agent/$Module/certificate $Agent/$Module/certificate/certificate.proto --go_out=plugins=grpc:$GOPATH/src
#### 

Agent="lbagent"
echo "Generating Protoc for $Agent"
Module="agent"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/agent.proto --go_out=plugins=grpc:$GOPATH/src

#### 

Agent="ipamagent"
echo "Generating Protoc for $Agent"
Module="ipaddressmanager"
echo "Generating $Module protoc"
protoc -I $Agent/$Module -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/${Module}.proto --go_out=plugins=grpc:$GOPATH/src
ChildModule="ipaddress"
echo "Generating $Module/$ChildModule protoc"
protoc -I $Agent/$Module -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/$ChildModule/${ChildModule}.proto --go_out=plugins=grpc:$GOPATH/src

#### 

Agent="guestagent"
echo "Generating Protoc for $Agent"
Module="admin"
echo "Generating $Module protoc"
ChildModule="exec"
echo "Generating $Module/$ChildModule protoc"
protoc -I $Agent/$Module -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/$ChildModule/${ChildModule}.proto --go_out=plugins=grpc:$GOPATH/src

#### 

Agent="cloudagent"
echo "Generating Protoc for $Agent"
Module="admin"
echo "Generating $Module protoc"
protoc -I $Agent/$Module/credentialmonitor -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/credentialmonitor/credentialmonitor.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/logging -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/logging/logging.proto --go_out=plugins=grpc:$GOPATH/src

Module="network"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualnetwork -I ./common  -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/virtualnetwork/virtualnetwork.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/loadbalancer -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/loadbalancer/loadbalancer.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/networkinterface -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/networkinterface/networkinterface.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/vippool -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/vippool/vippool.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/macpool -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/macpool/macpool.proto --go_out=plugins=grpc:$GOPATH/src

# Generate compute agent protoc
Module="compute"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualmachine -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/virtualmachine/virtualmachine.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/virtualmachinescaleset -I $Agent/$Module/virtualmachine -I $GOPATH/src/github.com/protocolbuffers/protobuf/src -I $Agent/network/networkinterface -I ./common $Agent/$Module/virtualmachinescaleset/virtualmachinescaleset.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/virtualmachineimage -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/virtualmachineimage/virtualmachineimage.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/galleryimage -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/galleryimage/galleryimage.proto  --go_out=plugins=grpc:$GOPATH/src

Module="storage"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualharddisk -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/virtualharddisk/virtualharddisk.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/container -I ./common -I $GOPATH/src/github.com/protocolbuffers/protobuf/src $Agent/$Module/container/container.proto  --go_out=plugins=grpc:$GOPATH/src

Module="cloud"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/group -I ./common $Agent/$Module/group/group.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/node -I ./common $Agent/$Module/node/node.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/kubernetes -I ./common $Agent/$Module/kubernetes/kubernetes.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/cluster -I $Agent/$Module/node -I ./common $Agent/$Module/cluster/cluster.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/location -I ./common $Agent/$Module/location/location.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/subscription -I ./common $Agent/$Module/subscription/subscription.proto  --go_out=plugins=grpc:$GOPATH/src


Module="security"
echo "Generating $Agent/$Module protoc"

protoc -I $Agent/$Module/identity -I ./common $Agent/$Module/identity/identity.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/keyvault/secret -I ./common $Agent/$Module/keyvault/secret/secret.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/keyvault/key -I ./common $Agent/$Module/keyvault/key/key.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/keyvault -I ./common -I $Agent/$Module/keyvault/secret $Agent/$Module/keyvault/keyvault.proto  --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/authentication -I ./common -I $Agent/$Module/identity $Agent/$Module/authentication/authentication.proto --go_out=plugins=grpc:$GOPATH/src
protoc -I $Agent/$Module/certificate -I ./common -I $Agent/$Module/certificate $Agent/$Module/certificate/certificate.proto --go_out=plugins=grpc:$GOPATH/src
