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
	// Group Contributor Role - has permissions to run any operation on the group resource
	GroupContributorRoleName = "GroupContributor"
	// Node Contributor Role - has permissions to create and get nodes
	NodeContributorRoleName = "NodeContributor"
	// MacPool Contributor Role - has permissions to run any operation on MacPools
	MacPoolContributorRoleName = "MacPoolContributor"
	// VipPool Contributor Role - has permissions to run any operation on VipPools
	VipPoolContributorRoleName = "VipPoolContributor"
	// LB Contributor Role - has permissions to run any operation on LBs
	LBContributorRoleName = "LBContributor"
	// Network Interface Contributor Role - has permissions to run any operation on network interfaces
	NIContributorRoleName = "NetworkInterfaceContributor"
	// VM Contributor Role - has permissions to run any operation on VMs
	VMContributorRoleName = "VMContributor"
	// BareMetalMachine Contributor Role - has permissions to run any operation on BareMetalMachines
	BMMContributorRoleName = "BareMetalMachineContributor"
	// VirtualNetwork Contributor Role - has permissions to run any operation on VirtualNetworks
	VNetContributorRoleName = "VirtualNetworkContributor"
	// VirtualHardDisk Contributor Role - has permissions to run any operation on VirtualHardDisks
	VHDContributorRoleName = "VirtualHardDiskContributor"
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
	// Group Reader Role - has permissions to run read operations on the group resource
	GroupReaderRoleName = "GroupReader"
	// Node Reader Role - has permissions to get nodes
	NodeReaderRoleName = "NodeReader"
	// MacPool Reader Role - has permissions to run read operations on MacPools
	MacPoolReaderRoleName = "MacPoolReader"
	// VipPool Reader Role - has permissions to run read operations on VipPools
	VipPoolReaderRoleName = "VipPoolReader"
	// LB Reader Role - has permissions to run read operations on LBs and interfaces
	LBReaderRoleName = "LBReader"
	// Network Interface Reader Role - has permissions to run read operations on network interfaces
	NIReaderRoleName = "NetworkInterfaceReader"
	// VM Reader Role - has permissions to run read operations on VMs
	VMReaderRoleName = "VMReader"
	// BareMetalMachine Reader Role - has permissions to run read operations on BareMetalMachines
	BMMReaderRoleName = "BareMetalMachineReader"
	// VirtualNetwork Reader Role - has permissions to run read operations on VirtualNetworks
	VNetReaderRoleName = "VirtualNetworkReader"
	// VirtualHardDisk Reader Role - has permissions to run read operations on VirtualHardDisks
	VHDReaderRoleName = "VirtualHardDiskReader"
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
)
