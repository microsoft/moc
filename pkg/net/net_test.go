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

	startip = net.ParseIP("192.168.0.0").To4()
	endip = net.ParseIP("192.168.0.255").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.168.0.0").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 24, prefixlen)

	startip = net.ParseIP("192.168.0.0").To4()
	endip = net.ParseIP("192.168.255.255").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.168.0.0").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 16, prefixlen)

	startip = net.ParseIP("192.168.0.5").To4()
	endip = net.ParseIP("192.168.0.5").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.168.0.5").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 32, prefixlen)

	startip = net.ParseIP("192.168.0.0").To4()
	endip = net.ParseIP("192.168.0.1").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.168.0.0").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 31, prefixlen)

	startip = net.ParseIP("192.168.0.0").To4()
	endip = net.ParseIP("192.168.0.15").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.168.0.0").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 28, prefixlen)

	startip = net.ParseIP("192.168.0.5").To4()
	endip = net.ParseIP("192.168.0.15").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.168.0.0").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 28, prefixlen)

	startip = net.ParseIP("192.168.0.1").To4()
	endip = net.ParseIP("192.168.0.14").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.168.0.0").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 28, prefixlen)

	startip = net.ParseIP("192.168.0.1").To4()
	endip = net.ParseIP("255.168.0.14").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("192.0.0.0").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 2, prefixlen)

	startip = net.ParseIP("128.168.0.1").To4()
	endip = net.ParseIP("255.168.0.14").To4()
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("128.0.0.0").To4(), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 1, prefixlen)

	startip = net.ParseIP("ffe0::")
	endip = net.ParseIP("fff0::")
	cidr, err = GetCIDR(startip, endip)
	require.NoError(t, err)
	require.Equal(t, net.ParseIP("ffe0::"), cidr.IP)
	prefixlen, _ = cidr.Mask.Size()
	require.Equal(t, 11, prefixlen)
}

func Test_GetBroadcastAddress(t *testing.T) {
	_, s1, _ := net.ParseCIDR("10.0.0.0/24")
	b1 := GetBroadcastAddress(*s1)
	require.Equal(t, b1, net.ParseIP("10.0.0.255"))

	_, s2, _ := net.ParseCIDR("2001::/64")
	b2 := GetBroadcastAddress(*s2)
	require.Equal(t, b2, net.ParseIP("2001::ffff:ffff:ffff:ffff"))
}

func Test_RangesOverlap(t *testing.T) {
	//exact overlap
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255")))

	//same start address different ending address
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("1.0.0.0"), net.ParseIP("1.0.255.255")))
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.128")))

	//same ending address different starting address
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("1.0.0.128"), net.ParseIP("1.0.0.255")))
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("0.0.0.128"), net.ParseIP("1.0.0.255")))

	//ranges are side by side
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("1.0.0.255"), net.ParseIP("2.0.0.0")))
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("0.0.0.255"), net.ParseIP("1.0.0.0")))

	//range 1 overlaps with the left side  of range 2
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("1.0.0.128"), net.ParseIP("2.0.0.0")))

	//range 1 overlaps with the right side  of range 2
	require.True(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("0.0.0.128"), net.ParseIP("1.0.0.128")))

	//no overlap: range 1 is to the left of range 2
	require.False(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("2.0.0.0"), net.ParseIP("2.0.0.255")))

	//no overlap: range 1 is to the right of range 2
	require.False(t, RangesOverlap(net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.255"), net.ParseIP("0.0.0.0"), net.ParseIP("0.0.0.255")))
}

func Test_IsRangeInCIDR(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	require.True(t, IsRangeInCIDR(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.5"), cidr))
	require.True(t, IsRangeInCIDR(net.ParseIP("10.0.0.250"), net.ParseIP("10.0.0.255"), cidr))
	require.True(t, IsRangeInCIDR(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), cidr))

	require.True(t, IsRangeInCIDR(net.ParseIP("9.0.0.0"), net.ParseIP("10.0.0.1"), cidr))
	require.True(t, IsRangeInCIDR(net.ParseIP("10.0.0.254"), net.ParseIP("11.0.0.0"), cidr))

	require.False(t, IsRangeInCIDR(net.ParseIP("9.0.0.0"), net.ParseIP("9.255.255.255"), cidr))
	require.False(t, IsRangeInCIDR(net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.255"), cidr))
}

func Test_RangeContains(t *testing.T) {
	require.True(t, RangeContains(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), net.ParseIP("10.0.0.0")))
	require.True(t, RangeContains(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), net.ParseIP("10.0.0.255")))
	require.True(t, RangeContains(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), net.ParseIP("10.0.0.1")))
	require.True(t, RangeContains(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), net.ParseIP("10.0.0.254")))

	require.False(t, RangeContains(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), net.ParseIP("9.255.255.255")))
	require.False(t, RangeContains(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255"), net.ParseIP("10.0.1.0")))
}
