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

	if len(startip) != len(endip) {
		return nil, fmt.Errorf("Can not compute CIDR for %s and %s.  Start and end range have different sizes (%d %d)", startip, endip, len(startip), len(endip))
	}

	var prefixlen uint = 0
	exit := false
	for i := 0; i < len(startip) && !exit; i++ {
		for j := 0; j < 8 && !exit; j++ {
			mask := byte(1 << (7 - j))
			if (startip[i] & mask) == (endip[i] & mask) {
				prefixlen++
			} else {
				exit = true
			}
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

func GetBroadcastAddress(cidr net.IPNet) net.IP {
	broadcastip := Or(cidr.IP, Not(net.IP(cidr.Mask)))
	if len(broadcastip) == net.IPv6len {
		return broadcastip
	}

	// IPv4 (10.0.0.255) addresses are typically represented as IPv4 mapped IPv6 address (0:0:0:0:0:FFFF:10.0.0.255) in the net.IP structure.
	// However, the net.IPNet structure stores the IPv4 address in a net.IPv4Len array.
	// So, we convert the ipv4 address to a ipv4 mapped ipv6 address to be consistent with net.ParseIP()
	// By converting to a ipv4 mappend ipv6 address callers can use this function in a more natural manner like
	// GetBroadcastAddress(cidr) == net.ParseIP(10.0.0.255)
	broadcastip = net.ParseIP(broadcastip.String())
	return broadcastip
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

func lessThan(left, right net.IP) bool {
	var l, r big.Int
	l.SetBytes(left)
	r.SetBytes(right)
	if l.Cmp(&r) == -1 {
		return true
	}
	return false
}

func greaterThan(left, right net.IP) bool {
	var l, r big.Int
	l.SetBytes(left)
	r.SetBytes(right)
	if l.Cmp(&r) == 1 {
		return true
	}
	return false
}

func RangesOverlap(range1start, range1end, range2start, range2end net.IP) bool {

	if lessThan(range1start, range2start) && lessThan(range2start, range1end) {
		return true
	}
	if lessThan(range2start, range1start) && lessThan(range1start, range2end) {
		return true
	}
	if range1start.Equal(range2start) || range1end.Equal(range2end) {
		return true
	}
	if range1end.Equal(range2start) || range1start.Equal(range2end) {
		return true
	}
	return false
}

func IsRangeInCIDR(start, end net.IP, cidr *net.IPNet) bool {
	if cidr.Contains(start) || cidr.Contains(end) {
		return true
	}
	return false
}

func RangeContains(start, end, ip net.IP) bool {
	if x := start.To4(); x != nil {
		start = x
	}
	if x := end.To4(); x != nil {
		end = x
	}
	if x := ip.To4(); x != nil {
		ip = x
	}

	if len(ip) != len(start) {
		return false
	}
	if len(ip) != len(end) {
		return false
	}

	if ip.Equal(start) || ip.Equal(end) {
		return true
	}
	if greaterThan(ip, start) && lessThan(ip, end) {
		return true
	}
	return false
}

//TODO: Create an IPRange class.
