#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the Apache v2.0 license.

# Make sure the script exits on first failure
# and returns the proper exit code to the 
# shell
set -e

####
Module="common"
echo "Generating $Module protoc"
protoc -I common common/moc_common_common.proto --csharp_out=:../bld/gen/
protoc -I common common/moc_common_computecommon.proto --csharp_out=:../bld/gen/
protoc -I common common/moc_common_nodeinfo.proto --csharp_out=:../bld/gen/
protoc -I common common/moc_common_networkcommon.proto --csharp_out=:../bld/gen/
protoc -I common common/admin/debug/moc_common_debug.proto --csharp_out=:../bld/gen/
protoc -I common common/admin/logging/moc_common_logging.proto --csharp_out=:../bld/gen/
protoc -I common common/admin/health/moc_common_health.proto --csharp_out=:../bld/gen/
protoc -I common common/admin/recovery/moc_common_recovery.proto --csharp_out=:../bld/gen/
protoc -I common common/admin/version/moc_common_version.proto --csharp_out=:../bld/gen/
protoc -I common common/moc_common_notification.proto --csharp_out=:../bld/gen/
protoc -I common common/moc_common_security.proto --csharp_out=:../bld/gen/
protoc -I common common/moc_common_storageinfo.proto --csharp_out=:../bld/gen/

#### 
Agent="nodeagent"
echo "Generating Protoc for $Agent"

Module="admin"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/credentialmonitor -I ./common $Agent/$Module/credentialmonitor/moc_nodeagent_credentialmonitor.proto  --csharp_out=:../bld/gen/

Module="network"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualnetwork -I ./common $Agent/$Module/virtualnetwork/moc_nodeagent_virtualnetwork.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/loadbalancer -I ./common $Agent/$Module/loadbalancer/moc_nodeagent_loadbalancer.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/virtualnetworkinterface -I ./common $Agent/$Module/virtualnetworkinterface/moc_nodeagent_virtualnetworkinterface.proto --csharp_out=:../bld/gen/

# Generate compute agent protoc
Module="compute"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualmachine -I ./common $Agent/$Module/virtualmachine/moc_nodeagent_virtualmachine.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/virtualmachinescaleset -I $Agent/$Module/virtualmachine -I $Agent/network/virtualnetworkinterface -I ./common $Agent/$Module/virtualmachinescaleset/moc_nodeagent_virtualmachinescaleset.proto --csharp_out=:../bld/gen/

Module="storage"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualharddisk -I ./common $Agent/$Module/virtualharddisk/moc_nodeagent_virtualharddisk.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/container -I ./common $Agent/$Module/container/moc_nodeagent_container.proto  --csharp_out=:../bld/gen/

Module="security"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/identity -I ./common $Agent/$Module/identity/moc_nodeagent_identity.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/keyvault/secret -I ./common $Agent/$Module/keyvault/secret/moc_nodeagent_secret.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/keyvault -I ./common -I $Agent/$Module/keyvault/secret $Agent/$Module/keyvault/moc_nodeagent_keyvault.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/authentication -I ./common -I $Agent/$Module/identity $Agent/$Module/authentication/moc_nodeagent_authentication.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/certificate -I ./common -I $Agent/$Module/certificate $Agent/$Module/certificate/moc_nodeagent_certificate.proto --csharp_out=:../bld/gen/

#### 

Agent="lbagent"
echo "Generating Protoc for $Agent"
Module="agent"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module -I ./common $Agent/$Module/moc_lbagent_agent.proto --csharp_out=:../bld/gen/

#### 

Agent="baremetalhostagent"
echo "Generating Protoc for $Agent"

Module="agent"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module -I ./common $Agent/$Module/moc_baremetalhostagent.proto --csharp_out=:../bld/gen/

#### 

Agent="ipamagent"
echo "Generating Protoc for $Agent"
Module="ipaddressmanager"
echo "Generating $Module protoc"
protoc -I $Agent/$Module -I ./common $Agent/$Module/moc_ipaddress_${Module}.proto --csharp_out=:../bld/gen/
ChildModule="ipaddress"
echo "Generating $Module/$ChildModule protoc"
protoc -I $Agent/$Module -I ./common $Agent/$Module/$ChildModule/moc_ipaddress_${ChildModule}.proto --csharp_out=:../bld/gen/

#### 

Agent="guestagent"
echo "Generating Protoc for $Agent"
Module="admin"
echo "Generating $Module protoc"
ChildModule="exec"
echo "Generating $Module/$ChildModule protoc"
protoc -I $Agent/$Module -I ./common $Agent/$Module/$ChildModule/moc_guestagent_${ChildModule}.proto --csharp_out=:../bld/gen/

#### 

Agent="cloudagent"
echo "Generating Protoc for $Agent"
Module="admin"
echo "Generating $Module protoc"
protoc -I $Agent/$Module/credentialmonitor -I ./common $Agent/$Module/credentialmonitor/moc_cloudagent_credentialmonitor.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/logging -I ./common $Agent/$Module/logging/moc_cloudagent_logging.proto --csharp_out=:../bld/gen/

Module="network"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualnetwork -I ./common  $Agent/$Module/virtualnetwork/moc_cloudagent_virtualnetwork.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/loadbalancer -I ./common $Agent/$Module/loadbalancer/moc_cloudagent_loadbalancer.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/networkinterface -I ./common $Agent/$Module/networkinterface/moc_cloudagent_networkinterface.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/vippool -I ./common $Agent/$Module/vippool/moc_cloudagent_vippool.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/macpool -I ./common $Agent/$Module/macpool/moc_cloudagent_macpool.proto --csharp_out=:../bld/gen/

# Generate compute agent protoc
Module="compute"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualmachine -I ./common $Agent/$Module/virtualmachine/moc_cloudagent_virtualmachine.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/virtualmachinescaleset -I $Agent/$Module/virtualmachine -I $Agent/network/networkinterface -I ./common $Agent/$Module/virtualmachinescaleset/moc_cloudagent_virtualmachinescaleset.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/virtualmachineimage -I ./common $Agent/$Module/virtualmachineimage/moc_cloudagent_virtualmachineimage.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/galleryimage -I ./common $Agent/$Module/galleryimage/moc_cloudagent_galleryimage.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/baremetalhost -I ./common -I $Agent/$Module/virtualmachine $Agent/$Module/baremetalhost/moc_cloudagent_baremetalhost.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/baremetalmachine -I ./common -I $Agent/$Module/virtualmachine $Agent/$Module/baremetalmachine/moc_cloudagent_baremetalmachine.proto --csharp_out=:../bld/gen/

Module="storage"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/virtualharddisk -I ./common $Agent/$Module/virtualharddisk/moc_cloudagent_virtualharddisk.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/container -I ./common $Agent/$Module/container/moc_cloudagent_container.proto  --csharp_out=:../bld/gen/

Module="cloud"
echo "Generating $Agent/$Module protoc"
protoc -I $Agent/$Module/group -I ./common $Agent/$Module/group/moc_cloudagent_group.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/node -I ./common $Agent/$Module/node/moc_cloudagent_node.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/kubernetes -I ./common $Agent/$Module/kubernetes/moc_cloudagent_kubernetes.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/cluster -I $Agent/$Module/node -I ./common $Agent/$Module/cluster/moc_cloudagent_cluster.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/location -I ./common $Agent/$Module/location/moc_cloudagent_location.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/subscription -I ./common $Agent/$Module/subscription/moc_cloudagent_subscription.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/controlplane -I ./common $Agent/$Module/controlplane/moc_cloudagent_controlplane.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/etcdcluster/etcdserver -I ./common $Agent/$Module/etcdcluster/etcdserver/moc_cloudagent_etcdserver.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/etcdcluster -I ./common -I $Agent/$Module/etcdcluster/etcdserver $Agent/$Module/etcdcluster/moc_cloudagent_etcdcluster.proto  --csharp_out=:../bld/gen/

Module="security"
echo "Generating $Agent/$Module protoc"

protoc -I $Agent/$Module/identity -I ./common -I $Agent/$Module/certificate $Agent/$Module/identity/moc_cloudagent_identity.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/roleassignment -I ./common $Agent/$Module/roleassignment/moc_cloudagent_roleassignment.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/keyvault/secret -I ./common $Agent/$Module/keyvault/secret/moc_cloudagent_secret.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/keyvault/key -I ./common $Agent/$Module/keyvault/key/moc_cloudagent_key.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/keyvault -I ./common -I $Agent/$Module/keyvault/secret $Agent/$Module/keyvault/moc_cloudagent_keyvault.proto  --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/authentication -I ./common -I $Agent/$Module/identity -I $Agent/$Module/certificate $Agent/$Module/authentication/moc_cloudagent_authentication.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/certificate -I ./common $Agent/$Module/certificate/moc_cloudagent_certificate.proto --csharp_out=:../bld/gen/
protoc -I $Agent/$Module/role -I ./common $Agent/$Module/role/moc_cloudagent_role.proto --csharp_out=:../bld/gen/
