// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
//
package net

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Or(t *testing.T) {
	var ip1, ip2, ip3 net.IP

	ip1 = net.ParseIP("255.255.0.0")
	ip2 = net.ParseIP("0.0.255.255")
	ip3 = Or(ip1, ip2)
	require.Equal(t, net.ParseIP("255.255.255.255"), ip3)

	ip1 = net.ParseIP("0.0.0.0")
	ip2 = net.ParseIP("0.0.0.0")
	ip3 = Or(ip1, ip2)
	require.Equal(t, net.ParseIP("0.0.0.0"), ip3)

	ip1 = net.ParseIP("255.255.255.255")
	ip2 = net.ParseIP("255.255.255.255")
	ip3 = Or(ip1, ip2)
	require.Equal(t, net.ParseIP("255.255.255.255"), ip3)

	ip1 = net.ParseIP("170.170.170.170")
	ip2 = net.ParseIP("85.85.85.85")
	ip3 = Or(ip1, ip2)
	require.Equal(t, net.ParseIP("255.255.255.255"), ip3)
}

func Test_Not(t *testing.T) {
	var ip1, ip2 net.IP

	ip1 = net.ParseIP("0.0.0.0").To4()
	ip2 = Not(ip1)
	require.Equal(t, net.ParseIP("255.255.255.255").To4(), ip2)

	ip1 = net.ParseIP("255.255.255.255").To4()
	ip2 = Not(ip1)
	require.Equal(t, net.ParseIP("0.0.0.0").To4(), ip2)

	ip1 = net.ParseIP("170.170.170.170").To4()
	ip2 = Not(ip1)
	require.Equal(t, net.ParseIP("85.85.85.85").To4(), ip2)

}

func Test_Increment(t *testing.T) {
	var ip1, ip2 net.IP

	ip1 = net.ParseIP("0.0.0.0")
	ip2 = Increment(ip1)
	require.Equal(t, net.ParseIP("0.0.0.1"), ip2)

	ip1 = net.ParseIP("0.0.0.255")
	ip2 = Increment(ip1)
	require.Equal(t, net.ParseIP("0.0.1.0"), ip2)

	ip1 = net.ParseIP("0.0.255.255")
	ip2 = Increment(ip1)
	require.Equal(t, net.ParseIP("0.1.0.0"), ip2)

	ip1 = net.ParseIP("0.255.255.255")
	ip2 = Increment(ip1)
	require.Equal(t, net.ParseIP("1.0.0.0"), ip2)

	ip1 = net.ParseIP("255.255.255.255").To4()
	ip2 = Increment(ip1)
	require.Equal(t, net.ParseIP("0.0.0.0").To4(), ip2)

}
func Test_Decrement(t *testing.T) {
	var ip1, ip2 net.IP

	ip1 = net.ParseIP("0.0.0.1")
	ip2 = Decrement(ip1)
	require.Equal(t, net.ParseIP("0.0.0.1"), ip1)
	require.Equal(t, net.ParseIP("0.0.0.0"), ip2)

	ip1 = net.ParseIP("255.255.255.255")
	ip2 = Decrement(ip1)
	require.Equal(t, net.ParseIP("255.255.255.254"), ip2)

	ip1 = net.ParseIP("255.255.255.0")
	ip2 = Decrement(ip1)
	require.Equal(t, net.ParseIP("255.255.254.255"), ip2)

	ip1 = net.ParseIP("255.255.0.0")
	ip2 = Decrement(ip1)
	require.Equal(t, net.ParseIP("255.254.255.255"), ip2)

	ip1 = net.ParseIP("255.0.0.0")
	ip2 = Decrement(ip1)
	require.Equal(t, net.ParseIP("254.255.255.255"), ip2)

	ip1 = net.ParseIP("0.0.0.0").To4()
	ip2 = Decrement(ip1)
	require.Equal(t, net.ParseIP("255.255.255.255").To4(), ip2)
}

func Test_PrefixesOverlap(t *testing.T) {
	_, cidr1, _ := net.ParseCIDR("192.10.0.0/16")
	_, cidr2, _ := net.ParseCIDR("192.10.0.0/16")
	require.True(t, PrefixesOverlap(*cidr1, *cidr2))
	require.True(t, PrefixesOverlap(*cidr2, *cidr1))

	_, cidr2, _ = net.ParseCIDR("192.10.0.0/32")
	require.True(t, PrefixesOverlap(*cidr1, *cidr2))
	require.True(t, PrefixesOverlap(*cidr2, *cidr1))

	_, cidr2, _ = net.ParseCIDR("192.10.1.0/24")
	require.True(t, PrefixesOverlap(*cidr1, *cidr2))
	require.True(t, PrefixesOverlap(*cidr2, *cidr1))

	_, cidr2, _ = net.ParseCIDR("192.10.255.255/32")
	require.True(t, PrefixesOverlap(*cidr1, *cidr2))
	require.True(t, PrefixesOverlap(*cidr2, *cidr1))

	_, cidr2, _ = net.ParseCIDR("192.11.0.0/24")
	require.False(t, PrefixesOverlap(*cidr1, *cidr2))
	require.False(t, PrefixesOverlap(*cidr2, *cidr1))
}

func Test_GetCIDR(t *testing.T) {
	var startip, endip net.IP
	var cidr *net.IPNet
	var err error
	var prefixlen int

	startip = net.ParseIP("192.168.0.0")
	endip = net.ParseIP("192.168.0.255")

	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, cidr.IP, net.ParseIP("192.168.0.0"))
	prefixlen, _ = cidr.Mask.Size()
	//require.Equal(t, 24, prefixlen)
	require.Equal(t, 120, prefixlen)

	startip = net.ParseIP("192.168.0.0")
	endip = net.ParseIP("192.168.255.255")

	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, cidr.IP, net.ParseIP("192.168.0.0"))
	prefixlen, _ = cidr.Mask.Size()
	//require.Equal(t, 16, prefixlen)
	require.Equal(t, 112, prefixlen)

	startip = net.ParseIP("192.168.0.1")
	endip = net.ParseIP("192.168.0.2")

	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, cidr.IP, net.ParseIP("192.168.0.0"))
	prefixlen, _ = cidr.Mask.Size()
	//require.Equal(t, 28, prefixlen)
	require.Equal(t, 120, prefixlen)

	startip = net.ParseIP("192.168.0.5")
	endip = net.ParseIP("192.168.0.5")

	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, cidr.IP, net.ParseIP("192.168.0.5"))
	prefixlen, _ = cidr.Mask.Size()
	//require.Equal(t, 24, prefixlen)
	require.Equal(t, 128, prefixlen)

}
