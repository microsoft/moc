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
	ReaderRoleName      = "Reader"
	GroupAccessRoleName = "GroupAccessRole"
	// LB Contributor Role - has permissions to run any operation on LBs and interfaces
	LBContributorRoleName = "LBContributor"
	// VM Contributor Role - has permissions to run any operation on VMs
	VMContributorRoleName = "VMContributor"
	// Node Contributor Role - has permissions to create and get nodes
	NodeContributorRoleName = "NodeContributor"
	// Group Contributor Role - has permissions to run any operation on the group resource
	GroupContributorRoleName = "GroupContributor"
	// Role Contributor Role - has permissions to operate on roles and assign them
	RoleContributorRoleName = "RoleContributor"
	// BareMetalMachine Contributor Role - has permissions to run any operation on BareMetalMachines
	BMMContributorRoleName = "BareMetalMachineContributor"
	// Identity Contributor Role - has permissions to run any operation on Identities
	IdentityContributorRoleName = "IdentityContributor"
	// KeyVault Contributor Role - has permissions to run any operation on KeyVaults
	KeyVaultContributorRoleName = "KeyVaultContributor"
	// VirtualNetwork Contributor Role - has permissions to run any operation on VirtualNetworks
	VNetContributorRoleName = "VirtualNetworkContributor"
	// Certificate Contributor Role - has permissions to run any operation on Certificates
	CertContributorRoleName = "CertificateContributor"
	// Certificate Reader Role - has permissions to run read operations on Certificates
	CertReaderRoleName = "CertificateReader"
)
