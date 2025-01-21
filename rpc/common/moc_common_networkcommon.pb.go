// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_common_networkcommon.proto

package common

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Protocol int32

const (
	Protocol_All    Protocol = 0
	Protocol_Tcp    Protocol = 1
	Protocol_Udp    Protocol = 2
	Protocol_Icmpv4 Protocol = 3
	Protocol_Icmpv6 Protocol = 4
)

var Protocol_name = map[int32]string{
	0: "All",
	1: "Tcp",
	2: "Udp",
	3: "Icmpv4",
	4: "Icmpv6",
}

var Protocol_value = map[string]int32{
	"All":    0,
	"Tcp":    1,
	"Udp":    2,
	"Icmpv4": 3,
	"Icmpv6": 4,
}

func (x Protocol) String() string {
	return proto.EnumName(Protocol_name, int32(x))
}

func (Protocol) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{0}
}

type IPAllocationMethod int32

const (
	IPAllocationMethod_Invalid IPAllocationMethod = 0
	IPAllocationMethod_Dynamic IPAllocationMethod = 1
	IPAllocationMethod_Static  IPAllocationMethod = 2
)

var IPAllocationMethod_name = map[int32]string{
	0: "Invalid",
	1: "Dynamic",
	2: "Static",
}

var IPAllocationMethod_value = map[string]int32{
	"Invalid": 0,
	"Dynamic": 1,
	"Static":  2,
}

func (x IPAllocationMethod) String() string {
	return proto.EnumName(IPAllocationMethod_name, int32(x))
}

func (IPAllocationMethod) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{1}
}

type IPPoolType int32

const (
	IPPoolType_VM      IPPoolType = 0
	IPPoolType_VIPPool IPPoolType = 1
)

var IPPoolType_name = map[int32]string{
	0: "VM",
	1: "VIPPool",
}

var IPPoolType_value = map[string]int32{
	"VM":      0,
	"VIPPool": 1,
}

func (x IPPoolType) String() string {
	return proto.EnumName(IPPoolType_name, int32(x))
}

func (IPPoolType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{2}
}

type NetworkType int32

const (
	NetworkType_VIRTUAL_NETWORK NetworkType = 0
	NetworkType_LOGICAL_NETWORK NetworkType = 1
	NetworkType_UNDEFINED       NetworkType = 2
)

var NetworkType_name = map[int32]string{
	0: "VIRTUAL_NETWORK",
	1: "LOGICAL_NETWORK",
	2: "UNDEFINED",
}

var NetworkType_value = map[string]int32{
	"VIRTUAL_NETWORK": 0,
	"LOGICAL_NETWORK": 1,
	"UNDEFINED":       2,
}

func (x NetworkType) String() string {
	return proto.EnumName(NetworkType_name, int32(x))
}

func (NetworkType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{3}
}

type IPVersion int32

const (
	IPVersion_IPv4 IPVersion = 0
	IPVersion_IPv6 IPVersion = 1
)

var IPVersion_name = map[int32]string{
	0: "IPv4",
	1: "IPv6",
}

var IPVersion_value = map[string]int32{
	"IPv4": 0,
	"IPv6": 1,
}

func (x IPVersion) String() string {
	return proto.EnumName(IPVersion_name, int32(x))
}

func (IPVersion) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{4}
}

type Dns struct {
	Servers              []string `protobuf:"bytes,1,rep,name=servers,proto3" json:"servers,omitempty"`
	Domain               string   `protobuf:"bytes,2,opt,name=domain,proto3" json:"domain,omitempty"`
	Search               []string `protobuf:"bytes,3,rep,name=search,proto3" json:"search,omitempty"`
	Options              []string `protobuf:"bytes,4,rep,name=options,proto3" json:"options,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Dns) Reset()         { *m = Dns{} }
func (m *Dns) String() string { return proto.CompactTextString(m) }
func (*Dns) ProtoMessage()    {}
func (*Dns) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{0}
}

func (m *Dns) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Dns.Unmarshal(m, b)
}
func (m *Dns) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Dns.Marshal(b, m, deterministic)
}
func (m *Dns) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Dns.Merge(m, src)
}
func (m *Dns) XXX_Size() int {
	return xxx_messageInfo_Dns.Size(m)
}
func (m *Dns) XXX_DiscardUnknown() {
	xxx_messageInfo_Dns.DiscardUnknown(m)
}

var xxx_messageInfo_Dns proto.InternalMessageInfo

func (m *Dns) GetServers() []string {
	if m != nil {
		return m.Servers
	}
	return nil
}

func (m *Dns) GetDomain() string {
	if m != nil {
		return m.Domain
	}
	return ""
}

func (m *Dns) GetSearch() []string {
	if m != nil {
		return m.Search
	}
	return nil
}

func (m *Dns) GetOptions() []string {
	if m != nil {
		return m.Options
	}
	return nil
}

type IPPoolInfo struct {
	Used                 string   `protobuf:"bytes,1,opt,name=used,proto3" json:"used,omitempty"`
	Available            string   `protobuf:"bytes,2,opt,name=available,proto3" json:"available,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *IPPoolInfo) Reset()         { *m = IPPoolInfo{} }
func (m *IPPoolInfo) String() string { return proto.CompactTextString(m) }
func (*IPPoolInfo) ProtoMessage()    {}
func (*IPPoolInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{1}
}

func (m *IPPoolInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IPPoolInfo.Unmarshal(m, b)
}
func (m *IPPoolInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IPPoolInfo.Marshal(b, m, deterministic)
}
func (m *IPPoolInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IPPoolInfo.Merge(m, src)
}
func (m *IPPoolInfo) XXX_Size() int {
	return xxx_messageInfo_IPPoolInfo.Size(m)
}
func (m *IPPoolInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_IPPoolInfo.DiscardUnknown(m)
}

var xxx_messageInfo_IPPoolInfo proto.InternalMessageInfo

func (m *IPPoolInfo) GetUsed() string {
	if m != nil {
		return m.Used
	}
	return ""
}

func (m *IPPoolInfo) GetAvailable() string {
	if m != nil {
		return m.Available
	}
	return ""
}

type IPPool struct {
	Name                 string      `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Type                 IPPoolType  `protobuf:"varint,2,opt,name=type,proto3,enum=moc.IPPoolType" json:"type,omitempty"`
	Start                string      `protobuf:"bytes,3,opt,name=start,proto3" json:"start,omitempty"`
	End                  string      `protobuf:"bytes,4,opt,name=end,proto3" json:"end,omitempty"`
	Info                 *IPPoolInfo `protobuf:"bytes,5,opt,name=info,proto3" json:"info,omitempty"`
	Tags                 *Tags       `protobuf:"bytes,6,opt,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *IPPool) Reset()         { *m = IPPool{} }
func (m *IPPool) String() string { return proto.CompactTextString(m) }
func (*IPPool) ProtoMessage()    {}
func (*IPPool) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{2}
}

func (m *IPPool) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IPPool.Unmarshal(m, b)
}
func (m *IPPool) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IPPool.Marshal(b, m, deterministic)
}
func (m *IPPool) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IPPool.Merge(m, src)
}
func (m *IPPool) XXX_Size() int {
	return xxx_messageInfo_IPPool.Size(m)
}
func (m *IPPool) XXX_DiscardUnknown() {
	xxx_messageInfo_IPPool.DiscardUnknown(m)
}

var xxx_messageInfo_IPPool proto.InternalMessageInfo

func (m *IPPool) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *IPPool) GetType() IPPoolType {
	if m != nil {
		return m.Type
	}
	return IPPoolType_VM
}

func (m *IPPool) GetStart() string {
	if m != nil {
		return m.Start
	}
	return ""
}

func (m *IPPool) GetEnd() string {
	if m != nil {
		return m.End
	}
	return ""
}

func (m *IPPool) GetInfo() *IPPoolInfo {
	if m != nil {
		return m.Info
	}
	return nil
}

func (m *IPPool) GetTags() *Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

type Route struct {
	NextHop              string   `protobuf:"bytes,1,opt,name=nextHop,proto3" json:"nextHop,omitempty"`
	DestinationPrefix    string   `protobuf:"bytes,2,opt,name=destinationPrefix,proto3" json:"destinationPrefix,omitempty"`
	Metric               uint32   `protobuf:"varint,3,opt,name=metric,proto3" json:"metric,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Route) Reset()         { *m = Route{} }
func (m *Route) String() string { return proto.CompactTextString(m) }
func (*Route) ProtoMessage()    {}
func (*Route) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{3}
}

func (m *Route) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Route.Unmarshal(m, b)
}
func (m *Route) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Route.Marshal(b, m, deterministic)
}
func (m *Route) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Route.Merge(m, src)
}
func (m *Route) XXX_Size() int {
	return xxx_messageInfo_Route.Size(m)
}
func (m *Route) XXX_DiscardUnknown() {
	xxx_messageInfo_Route.DiscardUnknown(m)
}

var xxx_messageInfo_Route proto.InternalMessageInfo

func (m *Route) GetNextHop() string {
	if m != nil {
		return m.NextHop
	}
	return ""
}

func (m *Route) GetDestinationPrefix() string {
	if m != nil {
		return m.DestinationPrefix
	}
	return ""
}

func (m *Route) GetMetric() uint32 {
	if m != nil {
		return m.Metric
	}
	return 0
}

// Resource reference is intended to be used as a general component of specific, named resource references
type ResourceReference struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ResourceReference) Reset()         { *m = ResourceReference{} }
func (m *ResourceReference) String() string { return proto.CompactTextString(m) }
func (*ResourceReference) ProtoMessage()    {}
func (*ResourceReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{4}
}

func (m *ResourceReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResourceReference.Unmarshal(m, b)
}
func (m *ResourceReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResourceReference.Marshal(b, m, deterministic)
}
func (m *ResourceReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResourceReference.Merge(m, src)
}
func (m *ResourceReference) XXX_Size() int {
	return xxx_messageInfo_ResourceReference.Size(m)
}
func (m *ResourceReference) XXX_DiscardUnknown() {
	xxx_messageInfo_ResourceReference.DiscardUnknown(m)
}

var xxx_messageInfo_ResourceReference proto.InternalMessageInfo

func (m *ResourceReference) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type NetworkSecurityGroupReference struct {
	ResourceRef          *ResourceReference `protobuf:"bytes,1,opt,name=resourceRef,proto3" json:"resourceRef,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *NetworkSecurityGroupReference) Reset()         { *m = NetworkSecurityGroupReference{} }
func (m *NetworkSecurityGroupReference) String() string { return proto.CompactTextString(m) }
func (*NetworkSecurityGroupReference) ProtoMessage()    {}
func (*NetworkSecurityGroupReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{5}
}

func (m *NetworkSecurityGroupReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NetworkSecurityGroupReference.Unmarshal(m, b)
}
func (m *NetworkSecurityGroupReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NetworkSecurityGroupReference.Marshal(b, m, deterministic)
}
func (m *NetworkSecurityGroupReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkSecurityGroupReference.Merge(m, src)
}
func (m *NetworkSecurityGroupReference) XXX_Size() int {
	return xxx_messageInfo_NetworkSecurityGroupReference.Size(m)
}
func (m *NetworkSecurityGroupReference) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkSecurityGroupReference.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkSecurityGroupReference proto.InternalMessageInfo

func (m *NetworkSecurityGroupReference) GetResourceRef() *ResourceReference {
	if m != nil {
		return m.ResourceRef
	}
	return nil
}

type ProbeReference struct {
	ResourceRef          *ResourceReference `protobuf:"bytes,1,opt,name=resourceRef,proto3" json:"resourceRef,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *ProbeReference) Reset()         { *m = ProbeReference{} }
func (m *ProbeReference) String() string { return proto.CompactTextString(m) }
func (*ProbeReference) ProtoMessage()    {}
func (*ProbeReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{6}
}

func (m *ProbeReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProbeReference.Unmarshal(m, b)
}
func (m *ProbeReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProbeReference.Marshal(b, m, deterministic)
}
func (m *ProbeReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProbeReference.Merge(m, src)
}
func (m *ProbeReference) XXX_Size() int {
	return xxx_messageInfo_ProbeReference.Size(m)
}
func (m *ProbeReference) XXX_DiscardUnknown() {
	xxx_messageInfo_ProbeReference.DiscardUnknown(m)
}

var xxx_messageInfo_ProbeReference proto.InternalMessageInfo

func (m *ProbeReference) GetResourceRef() *ResourceReference {
	if m != nil {
		return m.ResourceRef
	}
	return nil
}

type ProbeRequestPathReference struct {
	ResourceRef          *ResourceReference `protobuf:"bytes,1,opt,name=resourceRef,proto3" json:"resourceRef,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *ProbeRequestPathReference) Reset()         { *m = ProbeRequestPathReference{} }
func (m *ProbeRequestPathReference) String() string { return proto.CompactTextString(m) }
func (*ProbeRequestPathReference) ProtoMessage()    {}
func (*ProbeRequestPathReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{7}
}

func (m *ProbeRequestPathReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProbeRequestPathReference.Unmarshal(m, b)
}
func (m *ProbeRequestPathReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProbeRequestPathReference.Marshal(b, m, deterministic)
}
func (m *ProbeRequestPathReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProbeRequestPathReference.Merge(m, src)
}
func (m *ProbeRequestPathReference) XXX_Size() int {
	return xxx_messageInfo_ProbeRequestPathReference.Size(m)
}
func (m *ProbeRequestPathReference) XXX_DiscardUnknown() {
	xxx_messageInfo_ProbeRequestPathReference.DiscardUnknown(m)
}

var xxx_messageInfo_ProbeRequestPathReference proto.InternalMessageInfo

func (m *ProbeRequestPathReference) GetResourceRef() *ResourceReference {
	if m != nil {
		return m.ResourceRef
	}
	return nil
}

type FrontendIPConfigurationReference struct {
	ResourceRef          *ResourceReference `protobuf:"bytes,1,opt,name=resourceRef,proto3" json:"resourceRef,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *FrontendIPConfigurationReference) Reset()         { *m = FrontendIPConfigurationReference{} }
func (m *FrontendIPConfigurationReference) String() string { return proto.CompactTextString(m) }
func (*FrontendIPConfigurationReference) ProtoMessage()    {}
func (*FrontendIPConfigurationReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{8}
}

func (m *FrontendIPConfigurationReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FrontendIPConfigurationReference.Unmarshal(m, b)
}
func (m *FrontendIPConfigurationReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FrontendIPConfigurationReference.Marshal(b, m, deterministic)
}
func (m *FrontendIPConfigurationReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FrontendIPConfigurationReference.Merge(m, src)
}
func (m *FrontendIPConfigurationReference) XXX_Size() int {
	return xxx_messageInfo_FrontendIPConfigurationReference.Size(m)
}
func (m *FrontendIPConfigurationReference) XXX_DiscardUnknown() {
	xxx_messageInfo_FrontendIPConfigurationReference.DiscardUnknown(m)
}

var xxx_messageInfo_FrontendIPConfigurationReference proto.InternalMessageInfo

func (m *FrontendIPConfigurationReference) GetResourceRef() *ResourceReference {
	if m != nil {
		return m.ResourceRef
	}
	return nil
}

type BackendAddressPoolReference struct {
	ResourceRef          *ResourceReference `protobuf:"bytes,1,opt,name=resourceRef,proto3" json:"resourceRef,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *BackendAddressPoolReference) Reset()         { *m = BackendAddressPoolReference{} }
func (m *BackendAddressPoolReference) String() string { return proto.CompactTextString(m) }
func (*BackendAddressPoolReference) ProtoMessage()    {}
func (*BackendAddressPoolReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{9}
}

func (m *BackendAddressPoolReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BackendAddressPoolReference.Unmarshal(m, b)
}
func (m *BackendAddressPoolReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BackendAddressPoolReference.Marshal(b, m, deterministic)
}
func (m *BackendAddressPoolReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BackendAddressPoolReference.Merge(m, src)
}
func (m *BackendAddressPoolReference) XXX_Size() int {
	return xxx_messageInfo_BackendAddressPoolReference.Size(m)
}
func (m *BackendAddressPoolReference) XXX_DiscardUnknown() {
	xxx_messageInfo_BackendAddressPoolReference.DiscardUnknown(m)
}

var xxx_messageInfo_BackendAddressPoolReference proto.InternalMessageInfo

func (m *BackendAddressPoolReference) GetResourceRef() *ResourceReference {
	if m != nil {
		return m.ResourceRef
	}
	return nil
}

type NetworkReference struct {
	ResourceRef          *ResourceReference `protobuf:"bytes,1,opt,name=resourceRef,proto3" json:"resourceRef,omitempty"`
	NetworkType          NetworkType        `protobuf:"varint,2,opt,name=networkType,proto3,enum=moc.NetworkType" json:"networkType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *NetworkReference) Reset()         { *m = NetworkReference{} }
func (m *NetworkReference) String() string { return proto.CompactTextString(m) }
func (*NetworkReference) ProtoMessage()    {}
func (*NetworkReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{10}
}

func (m *NetworkReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NetworkReference.Unmarshal(m, b)
}
func (m *NetworkReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NetworkReference.Marshal(b, m, deterministic)
}
func (m *NetworkReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkReference.Merge(m, src)
}
func (m *NetworkReference) XXX_Size() int {
	return xxx_messageInfo_NetworkReference.Size(m)
}
func (m *NetworkReference) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkReference.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkReference proto.InternalMessageInfo

func (m *NetworkReference) GetResourceRef() *ResourceReference {
	if m != nil {
		return m.ResourceRef
	}
	return nil
}

func (m *NetworkReference) GetNetworkType() NetworkType {
	if m != nil {
		return m.NetworkType
	}
	return NetworkType_VIRTUAL_NETWORK
}

type SubnetReference struct {
	Network              *NetworkReference  `protobuf:"bytes,1,opt,name=network,proto3" json:"network,omitempty"`
	ResourceRef          *ResourceReference `protobuf:"bytes,2,opt,name=resourceRef,proto3" json:"resourceRef,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *SubnetReference) Reset()         { *m = SubnetReference{} }
func (m *SubnetReference) String() string { return proto.CompactTextString(m) }
func (*SubnetReference) ProtoMessage()    {}
func (*SubnetReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{11}
}

func (m *SubnetReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SubnetReference.Unmarshal(m, b)
}
func (m *SubnetReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SubnetReference.Marshal(b, m, deterministic)
}
func (m *SubnetReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SubnetReference.Merge(m, src)
}
func (m *SubnetReference) XXX_Size() int {
	return xxx_messageInfo_SubnetReference.Size(m)
}
func (m *SubnetReference) XXX_DiscardUnknown() {
	xxx_messageInfo_SubnetReference.DiscardUnknown(m)
}

var xxx_messageInfo_SubnetReference proto.InternalMessageInfo

func (m *SubnetReference) GetNetwork() *NetworkReference {
	if m != nil {
		return m.Network
	}
	return nil
}

func (m *SubnetReference) GetResourceRef() *ResourceReference {
	if m != nil {
		return m.ResourceRef
	}
	return nil
}

type PublicIPAddressReference struct {
	ResourceRef          *ResourceReference `protobuf:"bytes,1,opt,name=resourceRef,proto3" json:"resourceRef,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *PublicIPAddressReference) Reset()         { *m = PublicIPAddressReference{} }
func (m *PublicIPAddressReference) String() string { return proto.CompactTextString(m) }
func (*PublicIPAddressReference) ProtoMessage()    {}
func (*PublicIPAddressReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_ba09ae1dfdbe03d2, []int{12}
}

func (m *PublicIPAddressReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicIPAddressReference.Unmarshal(m, b)
}
func (m *PublicIPAddressReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicIPAddressReference.Marshal(b, m, deterministic)
}
func (m *PublicIPAddressReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicIPAddressReference.Merge(m, src)
}
func (m *PublicIPAddressReference) XXX_Size() int {
	return xxx_messageInfo_PublicIPAddressReference.Size(m)
}
func (m *PublicIPAddressReference) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicIPAddressReference.DiscardUnknown(m)
}

var xxx_messageInfo_PublicIPAddressReference proto.InternalMessageInfo

func (m *PublicIPAddressReference) GetResourceRef() *ResourceReference {
	if m != nil {
		return m.ResourceRef
	}
	return nil
}

func init() {
	proto.RegisterEnum("moc.Protocol", Protocol_name, Protocol_value)
	proto.RegisterEnum("moc.IPAllocationMethod", IPAllocationMethod_name, IPAllocationMethod_value)
	proto.RegisterEnum("moc.IPPoolType", IPPoolType_name, IPPoolType_value)
	proto.RegisterEnum("moc.NetworkType", NetworkType_name, NetworkType_value)
	proto.RegisterEnum("moc.IPVersion", IPVersion_name, IPVersion_value)
	proto.RegisterType((*Dns)(nil), "moc.Dns")
	proto.RegisterType((*IPPoolInfo)(nil), "moc.IPPoolInfo")
	proto.RegisterType((*IPPool)(nil), "moc.IPPool")
	proto.RegisterType((*Route)(nil), "moc.Route")
	proto.RegisterType((*ResourceReference)(nil), "moc.ResourceReference")
	proto.RegisterType((*NetworkSecurityGroupReference)(nil), "moc.NetworkSecurityGroupReference")
	proto.RegisterType((*ProbeReference)(nil), "moc.ProbeReference")
	proto.RegisterType((*ProbeRequestPathReference)(nil), "moc.ProbeRequestPathReference")
	proto.RegisterType((*FrontendIPConfigurationReference)(nil), "moc.FrontendIPConfigurationReference")
	proto.RegisterType((*BackendAddressPoolReference)(nil), "moc.BackendAddressPoolReference")
	proto.RegisterType((*NetworkReference)(nil), "moc.NetworkReference")
	proto.RegisterType((*SubnetReference)(nil), "moc.SubnetReference")
	proto.RegisterType((*PublicIPAddressReference)(nil), "moc.PublicIPAddressReference")
}

func init() { proto.RegisterFile("moc_common_networkcommon.proto", fileDescriptor_ba09ae1dfdbe03d2) }

var fileDescriptor_ba09ae1dfdbe03d2 = []byte{
	// 731 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x55, 0xef, 0x6f, 0xe3, 0x34,
	0x18, 0x6e, 0x9a, 0xae, 0xbb, 0xbe, 0xd5, 0xdd, 0x7c, 0x06, 0x8e, 0xf0, 0xe3, 0xa0, 0xe4, 0x84,
	0x98, 0x2a, 0xd4, 0x4a, 0xe3, 0x74, 0x42, 0x48, 0x20, 0xf5, 0xd6, 0x6d, 0x04, 0xb6, 0x2e, 0xca,
	0xda, 0x4e, 0x20, 0xa4, 0x29, 0x75, 0xdc, 0xd6, 0x5a, 0x62, 0x07, 0xdb, 0x29, 0xab, 0xc4, 0x07,
	0xfe, 0x21, 0xfe, 0x47, 0x64, 0x27, 0xa5, 0x85, 0xf1, 0x81, 0x0f, 0xfd, 0xf6, 0x3e, 0xaf, 0x9f,
	0xe7, 0xf1, 0x9b, 0x27, 0x8e, 0x03, 0x9f, 0x64, 0x82, 0xdc, 0x11, 0x91, 0x65, 0x82, 0xdf, 0x71,
	0xaa, 0x7f, 0x13, 0xf2, 0xbe, 0x44, 0xbd, 0x5c, 0x0a, 0x2d, 0xb0, 0x9b, 0x09, 0xf2, 0xe1, 0xfb,
	0x3b, 0xa4, 0xdd, 0x55, 0x9f, 0x81, 0x3b, 0xe4, 0x0a, 0x7b, 0x70, 0xa8, 0xa8, 0x5c, 0x51, 0xa9,
	0x3c, 0xa7, 0xe3, 0x1e, 0xb7, 0xa2, 0x0d, 0xc4, 0x2f, 0xa0, 0x99, 0x88, 0x2c, 0x66, 0xdc, 0xab,
	0x77, 0x9c, 0xe3, 0x56, 0x54, 0x21, 0xd3, 0x57, 0x34, 0x96, 0x64, 0xe9, 0xb9, 0x56, 0x50, 0x21,
	0xe3, 0x24, 0x72, 0xcd, 0x04, 0x57, 0x5e, 0xa3, 0x74, 0xaa, 0xa0, 0xff, 0x1d, 0x40, 0x10, 0x86,
	0x42, 0xa4, 0x01, 0x9f, 0x0b, 0x8c, 0xa1, 0x51, 0x28, 0x9a, 0x78, 0x8e, 0x75, 0xb5, 0x35, 0xfe,
	0x18, 0x5a, 0xf1, 0x2a, 0x66, 0x69, 0x3c, 0x4b, 0x69, 0xb5, 0xdd, 0xb6, 0xe1, 0xff, 0xe9, 0x40,
	0xb3, 0x34, 0x30, 0x62, 0x1e, 0x67, 0x74, 0x23, 0x36, 0x35, 0x7e, 0x05, 0x0d, 0xbd, 0xce, 0x4b,
	0xdd, 0xb3, 0x93, 0xa3, 0x5e, 0x26, 0x48, 0xaf, 0xa4, 0x8f, 0xd7, 0x39, 0x8d, 0xec, 0x22, 0x7e,
	0x17, 0x0e, 0x94, 0x8e, 0xa5, 0xf6, 0x5c, 0xab, 0x2c, 0x01, 0x46, 0xe0, 0x52, 0x9e, 0x78, 0x0d,
	0xdb, 0x33, 0xa5, 0x31, 0x63, 0x7c, 0x2e, 0xbc, 0x83, 0x8e, 0x73, 0xdc, 0xfe, 0x87, 0x99, 0x19,
	0x3e, 0xb2, 0x8b, 0xf8, 0x25, 0x34, 0x74, 0xbc, 0x50, 0x5e, 0xd3, 0x92, 0x5a, 0x96, 0x34, 0x8e,
	0x17, 0x2a, 0xb2, 0x6d, 0x7f, 0x01, 0x07, 0x91, 0x28, 0x34, 0x35, 0x91, 0x70, 0xfa, 0xa0, 0xbf,
	0x17, 0x79, 0x35, 0xf0, 0x06, 0xe2, 0x2f, 0xe1, 0x79, 0x42, 0x95, 0x66, 0x3c, 0x36, 0x11, 0x85,
	0x92, 0xce, 0xd9, 0x43, 0xf5, 0xe0, 0x8f, 0x17, 0x4c, 0xe4, 0x19, 0xd5, 0x92, 0x11, 0x3b, 0xfd,
	0xd3, 0xa8, 0x42, 0xfe, 0x17, 0xf0, 0x3c, 0xa2, 0x4a, 0x14, 0x92, 0xd0, 0x88, 0xce, 0xa9, 0xa4,
	0x9c, 0xd0, 0xff, 0x8a, 0xc8, 0xff, 0x09, 0x5e, 0x8e, 0xca, 0x13, 0x72, 0x43, 0x49, 0x21, 0x99,
	0x5e, 0x5f, 0x48, 0x51, 0xe4, 0x5b, 0xd1, 0xd7, 0xd0, 0x96, 0x5b, 0x27, 0xab, 0x6d, 0x9f, 0xbc,
	0xb0, 0x0f, 0xf6, 0x68, 0x87, 0x68, 0x97, 0xea, 0xff, 0x00, 0xcf, 0x42, 0x29, 0x66, 0x74, 0x1f,
	0x5e, 0x13, 0xf8, 0xa0, 0xf2, 0xfa, 0xb5, 0xa0, 0x4a, 0x87, 0xb1, 0x5e, 0xee, 0xc3, 0xf6, 0x17,
	0xe8, 0x9c, 0x4b, 0xc1, 0x35, 0xe5, 0x49, 0x10, 0x9e, 0x0a, 0x3e, 0x67, 0x8b, 0x42, 0xda, 0x7c,
	0xf7, 0xe1, 0x7e, 0x0b, 0x1f, 0xbd, 0x8d, 0xc9, 0x3d, 0xe5, 0xc9, 0x20, 0x49, 0x24, 0x55, 0xca,
	0x1c, 0x96, 0x7d, 0x18, 0xff, 0xe1, 0x00, 0xaa, 0xde, 0xda, 0x1e, 0xec, 0xf0, 0x09, 0xb4, 0xab,
	0x5b, 0x62, 0xbc, 0xfd, 0x5a, 0x90, 0x55, 0x8e, 0xb6, 0xfd, 0x68, 0x97, 0xe4, 0xff, 0x0e, 0x47,
	0x37, 0xc5, 0x8c, 0x53, 0xbd, 0x1d, 0xa0, 0x6f, 0xce, 0xb4, 0x65, 0x54, 0x9b, 0xbf, 0xb7, 0x6b,
	0xb1, 0xdd, 0x7b, 0xc3, 0xfa, 0xf7, 0xc4, 0xf5, 0xff, 0x1f, 0xc0, 0x18, 0xbc, 0xb0, 0x98, 0xa5,
	0x8c, 0x04, 0x61, 0x15, 0xed, 0x1e, 0x72, 0xe8, 0x7e, 0x0b, 0x4f, 0x42, 0x73, 0x03, 0x12, 0x91,
	0xe2, 0x43, 0x70, 0x07, 0x69, 0x8a, 0x6a, 0xa6, 0x18, 0x93, 0x1c, 0x39, 0xa6, 0x98, 0x24, 0x39,
	0xaa, 0x63, 0x80, 0x66, 0x40, 0xb2, 0x7c, 0xf5, 0x1a, 0xb9, 0x7f, 0xd7, 0x6f, 0x50, 0xa3, 0xfb,
	0x0d, 0xe0, 0x20, 0x1c, 0xa4, 0xa9, 0x20, 0xf6, 0x04, 0x5d, 0x51, 0xbd, 0x14, 0x09, 0x6e, 0xc3,
	0x61, 0xc0, 0x57, 0x71, 0xca, 0x12, 0x54, 0x33, 0x60, 0xb8, 0xe6, 0x71, 0xc6, 0x08, 0x72, 0x8c,
	0xf6, 0x46, 0xc7, 0x9a, 0x11, 0x54, 0xef, 0x7e, 0xb6, 0xb9, 0x08, 0x4d, 0xb8, 0xb8, 0x09, 0xf5,
	0xe9, 0x55, 0x49, 0x9f, 0x96, 0x6d, 0xe4, 0x74, 0xcf, 0xa1, 0xbd, 0xf3, 0x36, 0xf0, 0x3b, 0x70,
	0x34, 0x0d, 0xa2, 0xf1, 0x64, 0x70, 0x79, 0x37, 0x3a, 0x1b, 0xdf, 0x5e, 0x47, 0x3f, 0xa2, 0x9a,
	0x69, 0x5e, 0x5e, 0x5f, 0x04, 0xa7, 0x3b, 0x4d, 0x07, 0x3f, 0x85, 0xd6, 0x64, 0x34, 0x3c, 0x3b,
	0x0f, 0x46, 0x67, 0x43, 0x54, 0xef, 0x7e, 0x0a, 0xad, 0x20, 0x9c, 0x52, 0xa9, 0x98, 0xe0, 0xf8,
	0x09, 0x34, 0x82, 0x70, 0xf5, 0x1a, 0xd5, 0xaa, 0xea, 0x0d, 0x72, 0xde, 0x7e, 0xfe, 0xf3, 0xab,
	0x05, 0xd3, 0xcb, 0x62, 0xd6, 0x23, 0x22, 0xeb, 0x67, 0x8c, 0x48, 0xa1, 0xc4, 0x5c, 0xf7, 0x33,
	0x41, 0xfa, 0x32, 0x27, 0xfd, 0xf2, 0x67, 0x31, 0x6b, 0xda, 0xbf, 0xc5, 0x57, 0x7f, 0x05, 0x00,
	0x00, 0xff, 0xff, 0xb7, 0x62, 0xb5, 0x86, 0x6d, 0x06, 0x00, 0x00,
}
