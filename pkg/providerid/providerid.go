// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.

package providerid

import (
	"strings"

	"github.com/microsoft/moc/pkg/errors"
)

const (
	ProviderName     string = "moc"
	ProviderIDPrefix string = ProviderName + "://"
)

type HostType string

const (
	HostTypeVM        HostType = "vm"
	HostTypeBareMetal HostType = "baremetal"
)

func FormatInstanceID(hostType HostType, machineName string) string {
	switch hostType {
	case HostTypeVM:
		// Don't append the host type for VMs to maintain consistency with previous versions.
		return machineName

	default:
		return string(hostType) + "/" + machineName
	}
}

func FormatProviderID(hostType HostType, machineName string) string {
	return ProviderIDPrefix + FormatInstanceID(hostType, machineName)
}

func ParseProviderID(providerID string) (HostType, string, error) {
	if providerID == "" {
		return "", "", errors.Wrap(errors.NotFound, "providerID is empty")
	}

	withoutPrefix := strings.TrimPrefix(providerID, ProviderIDPrefix)
	if withoutPrefix == providerID {
		return "", "", errors.Wrapf(errors.InvalidInput, "providerID is missing expected prefix (%s): %s", ProviderIDPrefix, providerID)
	}

	withoutPrefix = strings.TrimSpace(withoutPrefix)

	// Parse out the host type.
	split := strings.SplitN(withoutPrefix, "/", 2)
	if len(split) < 1 {
		return "", "", errors.Wrap(errors.InvalidInput, "providerID is invalid")
	}

	if len(split) == 1 {
		// VMs don't have the host type prefix.
		return HostTypeVM, split[0], nil
	}

	hostType := HostType(split[0])
	machineName := split[1]

	if hostType != HostTypeBareMetal {
		return "", "", errors.Wrapf(errors.InvalidInput, "providerID contains unknown host type: %s", string(hostType))
	}

	return hostType, machineName, nil
}
