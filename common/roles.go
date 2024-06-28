// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package wssdcommon

// Default Roles
const (
	// Admin Role - has full access permissions
	OwnerRoleName = "Owner"
	// Contributor Role - has full access, but can't assign or create roles
	ContributorRoleName = "Contributor"
	// Reader Role - has access to view all resource, but can't make changes
	ReaderRoleName = "Reader"
	// Location Contributor Role - has permissions to run any operation on the location resource
	LocationContributorRoleName = "LocationContributor"
	// Group Contributor Role - has permissions to run any operation on the group resource
	GroupContributorRoleName = "GroupContributor"
	// Node Contributor Role - has permissions to create and get nodes
	NodeContributorRoleName = "NodeContributor"
	// Cluster Contributor Role - has permissions to create and get clusters
	ClusterContributorRoleName = "ClusterContributor"
	// MacPool Contributor Role - has permissions to run any operation on mac pools
	MacPoolContributorRoleName = "MacPoolContributor"
	// VipPool Contributor Role - has permissions to run any operation on vip pools
	VipPoolContributorRoleName = "VipPoolContributor"
	// GalleryImage Contributor Role - has permissions to run any operation on gallery images
	GalleryImageContributorRoleName = "GalleryImageContributor"
	// ControlPlane Contributor Role - has permissions to run any operation on control planes
	ControlPlaneContributorRoleName = "ControlPlaneContributor"
	// StorageContainer Contributor Role - has permissions to run any operation on storage containers
	StorageContainerContributorRoleName = "StorageContainerContributor"
	// LB Contributor Role - has permissions to run any operation on LBs
	LBContributorRoleName = "LBContributor"
	// Network Interface Contributor Role - has permissions to run any operation on network interfaces
	NIContributorRoleName = "NetworkInterfaceContributor"
	// Network Security Group Contributor Role - has permissions to run any operation on network security groups
	NSGContributorRoleName = "NetworkSecurityGroupContributor"
	// PublicIPAddress Contributor Role - has permissions to run any operation on public IP address
	PublicIPAddressRoleName = "PublicIPAddressContributor"
	// VM Contributor Role - has permissions to run any operation on VMs
	VMContributorRoleName = "VMContributor"
	// VM Updater Role - has permissions to update VMs
	VMUpdaterRoleName = "VMUpdater"
	// VirtualMachineImage Contributor Role - has permissions to run any operation on VirtualMachineImages
	VMIContributorRoleName = "VirtualMachineImageContributor"
	// VirtualMachineScaleSet Contributor Role - has permissions to run any operation on VirtualMachineScaleSets
	VMSSContributorRoleName = "VMSSContributor"
	// BareMetalMachine Contributor Role - has permissions to run any operation on BareMetalMachines
	BMMContributorRoleName = "BareMetalMachineContributor"
	// VirtualNetwork Contributor Role - has permissions to run any operation on VirtualNetworks
	VNetContributorRoleName = "VirtualNetworkContributor"
	// LogicalNetwork Contributor Role - has permissions to run any operation on LogicalNetworks
	LNetContributorRoleName = "LogicalNetworkContributor"
	// VirtualHardDisk Contributor Role - has permissions to run any operation on VirtualHardDisks
	VHDContributorRoleName = "VirtualHardDiskContributor"
	// Kubernetes Contributor Role - has permissions to run any operation on Kubernetes resources
	KubernetesContributorRoleName = "KubernetesContributor"
	// EtcdCluster Contributor Role - has permissions to run any operation on EtcdClusters
	EtcdClusterContributorRoleName = "EtcdClusterContributor"
	// EtcdServer Contributor Role - has permissions to run any operation on EtcdServers
	EtcdServerContributorRoleName = "EtcdServerContributor"
	// Role Contributor Role - has permissions to operate on roles and assign them
	RoleContributorRoleName = "RoleContributor"
	// Identity Contributor Role - has permissions to run any operation on Identities
	IdentityContributorRoleName = "IdentityContributor"
	// Certificate Contributor Role - has permissions to run any operation on Certificates
	CertContributorRoleName = "CertificateContributor"
	// KeyVault Contributor Role - has permissions to run any operation on KeyVaults
	KeyVaultContributorRoleName = "KeyVaultContributor"
	// Key Contributor role - has permissions to run any operation on Keys
	KeyContributorRoleName = "KeyContributor"
	// Secret Contributor role - has permissions to run any operation on Secrets
	SecretContributorRoleName = "SecretContributor"
	// AvailabilitySet Contributor Role - has permissions to run any operations on AvailabilitySets
	AvailabilitySetContributorRoleName = "AvailabilitySetContributor"
	// Location Reader role - has permissions to run read operations on locations
	LocationReaderRoleName = "LocationReader"
	// Group Reader Role - has permissions to run read operations on the group resource
	GroupReaderRoleName = "GroupReader"
	// Node Reader Role - has permissions to get nodes
	NodeReaderRoleName = "NodeReader"
	// Cluster Reader Role - has permissions to get clusters
	ClusterReaderRoleName = "ClusterReader"
	// MacPool Reader Role - has permissions to run read operations on mac pools
	MacPoolReaderRoleName = "MacPoolReader"
	// VipPool Reader Role - has permissions to run read operations on vip pools
	VipPoolReaderRoleName = "VipPoolReader"
	// GalleryImage Reader Role - has permissions to run read operations on gallery images
	GalleryImageReaderRoleName = "GalleryImageReader"
	// ControlPlane Reader Role - has permissions to run read operations on control planes
	ControlPlaneReaderRoleName = "ControlPlaneReader"
	// StorageContainer Reader Role - has permissions to run read operations on storage containers
	StorageContainerReaderRoleName = "StorageContainerReader"
	// LB Reader Role - has permissions to run read operations on LBs and interfaces
	LBReaderRoleName = "LBReader"
	// Network Interface Reader Role - has permissions to run read operations on network interfaces
	NIReaderRoleName = "NetworkInterfaceReader"
	// Network Security Group Reader Role - has permissions to run read operations on network security groups
	NSGReaderRoleName = "NetworkSecurityGroupReader"
	// PublicIPAddress Reader Role - has permissions to run read operation on public IP address
	PIPReaderRoleName = "PublicIPAddressReader"
	// VM Reader Role - has permissions to run read operations on VMs
	VMReaderRoleName = "VMReader"
	// VirtualMachineImage Reader Role - has permissions to run read operations on VirtualMachineImages
	VMIReaderRoleName = "VirtualMachineImageReader"
	// VirtualMachineScaleSet Reader Role - has permissions to run read operations on VirtualMachineScaleSets
	VMSSReaderRoleName = "VMSSReader"
	// BareMetalMachine Reader Role - has permissions to run read operations on BareMetalMachines
	BMMReaderRoleName = "BareMetalMachineReader"
	// VirtualNetwork Reader Role - has permissions to run read operations on VirtualNetworks
	VNetReaderRoleName = "VirtualNetworkReader"
	// LogicalNetwork Reader Role - has permissions to run read operations on LogicalNetworks
	LNetReaderRoleName = "LogicalNetworkReader"
	// VirtualHardDisk Reader Role - has permissions to run read operations on VirtualHardDisks
	VHDReaderRoleName = "VirtualHardDiskReader"
	// Kubernetes Reader Role - has permissions to run read operations on Kubernetes resources
	KubernetesReaderRoleName = "KubernetesReader"
	// EtcdCluster Reader Role - has permissions to run read operations on EtcdClusters
	EtcdClusterReaderRoleName = "EtcdClusterReader"
	// EtcdServer Reader Role - has permissions to run read operations on EtcdServers
	EtcdServerReaderRoleName = "EtcdServerReader"
	// Identity Reader Role - has permissions to run read operations on Identities
	IdentityReaderRoleName = "IdentityReader"
	// Role Reader Role - has permissions to operate on roles and assign them
	RoleReaderRoleName = "RoleReader"
	// Certificate Reader Role - has permissions to run read operations on Certificates
	CertReaderRoleName = "CertificateReader"
	// KeyVault Reader Role - has permissions to run read operations on KeyVaults
	KeyVaultReaderRoleName = "KeyVaultReader"
	// Key Reader role - has permissions to run read operations on Keys
	KeyReaderRoleName = "KeyReader"
	// Secret Reader role - has permissions to run read operations on Secrets
	SecretReaderRoleName = "SecretReader"
	// Health Reader role - has permissions to read agent health information
	HealthReaderRoleName = "HealthReader"
	// AvailabilitySet Reader Role - has permissions to run read operations on AvailabilitySets
	AvailabilitySetReaderRoleName = "AvailabilitySetReader"
	// Certificate Signer Role - has permissions to run sign and renew operations on Certificates
	CertSignerRoleName = "CertificateSigner"
)
