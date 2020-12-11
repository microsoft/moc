// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package net

import (
	"fmt"
	"math/big"
	"net"
)

func GetIPAddress() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

func StringToNetIPAddress(ipString string) net.IP {
	return net.ParseIP(ipString)
}

func ParseMAC(macString string) (net.HardwareAddr, error) {
	var macInt big.Int

	// Hyper-V uses non-standard MAC address formats (with no colons and no dashes)
	_, success := macInt.SetString(macString, 16)
	if success {
		macBytes := macInt.Bytes()
		for i := len(macBytes); i < 6; i++ {
			macBytes = append([]byte{0}, macBytes...)
		}
		hardwareAddr := net.HardwareAddr(macBytes)
		return hardwareAddr, nil
	}

	hardwareAddr, err := net.ParseMAC(macString)
	if err != nil {
		return nil, err
	}

	return hardwareAddr, nil
}

func Or(ip, ip1 net.IP) net.IP {
	b := make([]byte, len(ip))
	for i := 0; i < len(ip); i++ {
		b[i] = ip[i] | ip1[i]
	}
	return b
}

func Not(ip net.IP) net.IP {
	b := make([]byte, len(ip))
	for i := 0; i < len(ip); i++ {
		b[i] = ^ip[i]
	}
	return b
}

func Increment(ip net.IP) net.IP {
	newip := make([]byte, len(ip))
	copy(newip, ip)
	for i := len(ip) - 1; i >= 0; i-- {
		newip[i] = ip[i] + 1
		if newip[i] > 0 {
			break
		}
	}
	return newip
}

func Decrement(ip net.IP) net.IP {
	newip := make([]byte, len(ip))
	copy(newip, ip)
	for i := len(ip) - 1; i >= 0; i-- {
		newip[i] = ip[i] - 1
		if newip[i] < 255 {
			break
		}
	}
	return newip
}

func GetCIDR(startip, endip net.IP) (*net.IPNet, error) {

	var prefixlen uint = 0
	for i := 0; i < len(startip); i++ {
		if startip[i] == endip[i] {
			prefixlen += 8
		} else {
			break
		}
	}
	mask := net.CIDRMask(int(prefixlen), len(startip)*8)

	//Find the start of the CIDR we need to allocate
	rangeStartIP := startip.Mask(mask)
	//fmt.Printf("the range to allocate for %s - %s is: %s\\%d\n", sip, eip, rangeStartIP, prefixlen)

	return &net.IPNet{
		IP:   rangeStartIP,
		Mask: mask,
	}, nil
}

func PrefixesOverlap(cidr1 net.IPNet, cidr2 net.IPNet) bool {
	if cidr1.Contains(cidr2.IP) || cidr2.Contains(cidr1.IP) {
		return true
	}
	return false
}

func GetNetworkInterface() (string, error) {
	// get primary public IP address
	primaryPublicIP, err := GetIPAddress()
	if err != nil {
		return "", err
	}

	networkInterfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, networkInterface := range networkInterfaces {
		// return this interface iff it contains the
		// primary public IP address

		// skip down interface
		if networkInterface.Flags&net.FlagUp == 0 {
			continue
		}
		// skip loopback
		if networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// list of unicast interface addresses for specific interface
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return "", err
		}
		// network end point address
		for _, address := range addresses {
			var ip net.IP
			switch typedAddress := address.(type) {
			case *net.IPNet:
				ip = typedAddress.IP
			case *net.IPAddr:
				ip = typedAddress.IP
			}
			// skip loopback or wrong type
			if ip == nil || ip.IsLoopback() {
				continue
			}

			if ip.String() == primaryPublicIP {
				// return this interface
				return networkInterface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("No network interfaces found")
}
