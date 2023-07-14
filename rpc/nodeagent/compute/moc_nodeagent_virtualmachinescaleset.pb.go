// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_nodeagent_virtualmachinescaleset.proto

package compute

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	common "github.com/microsoft/moc/rpc/common"
	network "github.com/microsoft/moc/rpc/nodeagent/network"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

type VirtualMachineScaleSetRequest struct {
	VirtualMachineScaleSetSystems []*VirtualMachineScaleSet `protobuf:"bytes,1,rep,name=VirtualMachineScaleSetSystems,proto3" json:"VirtualMachineScaleSetSystems,omitempty"`
	OperationType                 common.Operation          `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral          struct{}                  `json:"-"`
	XXX_unrecognized              []byte                    `json:"-"`
	XXX_sizecache                 int32                     `json:"-"`
}

func (m *VirtualMachineScaleSetRequest) Reset()         { *m = VirtualMachineScaleSetRequest{} }
func (m *VirtualMachineScaleSetRequest) String() string { return proto.CompactTextString(m) }
func (*VirtualMachineScaleSetRequest) ProtoMessage()    {}
func (*VirtualMachineScaleSetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_c094179683a8aea5, []int{0}
}

func (m *VirtualMachineScaleSetRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualMachineScaleSetRequest.Unmarshal(m, b)
}
func (m *VirtualMachineScaleSetRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualMachineScaleSetRequest.Marshal(b, m, deterministic)
}
func (m *VirtualMachineScaleSetRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualMachineScaleSetRequest.Merge(m, src)
}
func (m *VirtualMachineScaleSetRequest) XXX_Size() int {
	return xxx_messageInfo_VirtualMachineScaleSetRequest.Size(m)
}
func (m *VirtualMachineScaleSetRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualMachineScaleSetRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualMachineScaleSetRequest proto.InternalMessageInfo

func (m *VirtualMachineScaleSetRequest) GetVirtualMachineScaleSetSystems() []*VirtualMachineScaleSet {
	if m != nil {
		return m.VirtualMachineScaleSetSystems
	}
	return nil
}

func (m *VirtualMachineScaleSetRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type VirtualMachineScaleSetResponse struct {
	VirtualMachineScaleSetSystems []*VirtualMachineScaleSet `protobuf:"bytes,1,rep,name=VirtualMachineScaleSetSystems,proto3" json:"VirtualMachineScaleSetSystems,omitempty"`
	Result                        *wrappers.BoolValue       `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                         string                    `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral          struct{}                  `json:"-"`
	XXX_unrecognized              []byte                    `json:"-"`
	XXX_sizecache                 int32                     `json:"-"`
}

func (m *VirtualMachineScaleSetResponse) Reset()         { *m = VirtualMachineScaleSetResponse{} }
func (m *VirtualMachineScaleSetResponse) String() string { return proto.CompactTextString(m) }
func (*VirtualMachineScaleSetResponse) ProtoMessage()    {}
func (*VirtualMachineScaleSetResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_c094179683a8aea5, []int{1}
}

func (m *VirtualMachineScaleSetResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualMachineScaleSetResponse.Unmarshal(m, b)
}
func (m *VirtualMachineScaleSetResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualMachineScaleSetResponse.Marshal(b, m, deterministic)
}
func (m *VirtualMachineScaleSetResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualMachineScaleSetResponse.Merge(m, src)
}
func (m *VirtualMachineScaleSetResponse) XXX_Size() int {
	return xxx_messageInfo_VirtualMachineScaleSetResponse.Size(m)
}
func (m *VirtualMachineScaleSetResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualMachineScaleSetResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualMachineScaleSetResponse proto.InternalMessageInfo

func (m *VirtualMachineScaleSetResponse) GetVirtualMachineScaleSetSystems() []*VirtualMachineScaleSet {
	if m != nil {
		return m.VirtualMachineScaleSetSystems
	}
	return nil
}

func (m *VirtualMachineScaleSetResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *VirtualMachineScaleSetResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type Sku struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Capacity             int64    `protobuf:"varint,2,opt,name=capacity,proto3" json:"capacity,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Sku) Reset()         { *m = Sku{} }
func (m *Sku) String() string { return proto.CompactTextString(m) }
func (*Sku) ProtoMessage()    {}
func (*Sku) Descriptor() ([]byte, []int) {
	return fileDescriptor_c094179683a8aea5, []int{2}
}

func (m *Sku) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Sku.Unmarshal(m, b)
}
func (m *Sku) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Sku.Marshal(b, m, deterministic)
}
func (m *Sku) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Sku.Merge(m, src)
}
func (m *Sku) XXX_Size() int {
	return xxx_messageInfo_Sku.Size(m)
}
func (m *Sku) XXX_DiscardUnknown() {
	xxx_messageInfo_Sku.DiscardUnknown(m)
}

var xxx_messageInfo_Sku proto.InternalMessageInfo

func (m *Sku) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Sku) GetCapacity() int64 {
	if m != nil {
		return m.Capacity
	}
	return 0
}

type NetworkConfigurationScaleSet struct {
	Interfaces           []*network.VirtualNetworkInterface `protobuf:"bytes,1,rep,name=interfaces,proto3" json:"interfaces,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                           `json:"-"`
	XXX_unrecognized     []byte                             `json:"-"`
	XXX_sizecache        int32                              `json:"-"`
}

func (m *NetworkConfigurationScaleSet) Reset()         { *m = NetworkConfigurationScaleSet{} }
func (m *NetworkConfigurationScaleSet) String() string { return proto.CompactTextString(m) }
func (*NetworkConfigurationScaleSet) ProtoMessage()    {}
func (*NetworkConfigurationScaleSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_c094179683a8aea5, []int{3}
}

func (m *NetworkConfigurationScaleSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NetworkConfigurationScaleSet.Unmarshal(m, b)
}
func (m *NetworkConfigurationScaleSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NetworkConfigurationScaleSet.Marshal(b, m, deterministic)
}
func (m *NetworkConfigurationScaleSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkConfigurationScaleSet.Merge(m, src)
}
func (m *NetworkConfigurationScaleSet) XXX_Size() int {
	return xxx_messageInfo_NetworkConfigurationScaleSet.Size(m)
}
func (m *NetworkConfigurationScaleSet) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkConfigurationScaleSet.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkConfigurationScaleSet proto.InternalMessageInfo

func (m *NetworkConfigurationScaleSet) GetInterfaces() []*network.VirtualNetworkInterface {
	if m != nil {
		return m.Interfaces
	}
	return nil
}

type VirtualMachineProfile struct {
	Vmprefix             string                          `protobuf:"bytes,1,opt,name=vmprefix,proto3" json:"vmprefix,omitempty"`
	Network              *NetworkConfigurationScaleSet   `protobuf:"bytes,2,opt,name=network,proto3" json:"network,omitempty"`
	Storage              *StorageConfiguration           `protobuf:"bytes,3,opt,name=storage,proto3" json:"storage,omitempty"`
	Os                   *OperatingSystemConfiguration   `protobuf:"bytes,4,opt,name=os,proto3" json:"os,omitempty"`
	Hardware             *HardwareConfiguration          `protobuf:"bytes,5,opt,name=hardware,proto3" json:"hardware,omitempty"`
	Security             *SecurityConfiguration          `protobuf:"bytes,6,opt,name=security,proto3" json:"security,omitempty"`
	GuestAgent           *common.GuestAgentConfiguration `protobuf:"bytes,7,opt,name=guestAgent,proto3" json:"guestAgent,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                        `json:"-"`
	XXX_unrecognized     []byte                          `json:"-"`
	XXX_sizecache        int32                           `json:"-"`
}

func (m *VirtualMachineProfile) Reset()         { *m = VirtualMachineProfile{} }
func (m *VirtualMachineProfile) String() string { return proto.CompactTextString(m) }
func (*VirtualMachineProfile) ProtoMessage()    {}
func (*VirtualMachineProfile) Descriptor() ([]byte, []int) {
	return fileDescriptor_c094179683a8aea5, []int{4}
}

func (m *VirtualMachineProfile) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualMachineProfile.Unmarshal(m, b)
}
func (m *VirtualMachineProfile) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualMachineProfile.Marshal(b, m, deterministic)
}
func (m *VirtualMachineProfile) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualMachineProfile.Merge(m, src)
}
func (m *VirtualMachineProfile) XXX_Size() int {
	return xxx_messageInfo_VirtualMachineProfile.Size(m)
}
func (m *VirtualMachineProfile) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualMachineProfile.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualMachineProfile proto.InternalMessageInfo

func (m *VirtualMachineProfile) GetVmprefix() string {
	if m != nil {
		return m.Vmprefix
	}
	return ""
}

func (m *VirtualMachineProfile) GetNetwork() *NetworkConfigurationScaleSet {
	if m != nil {
		return m.Network
	}
	return nil
}

func (m *VirtualMachineProfile) GetStorage() *StorageConfiguration {
	if m != nil {
		return m.Storage
	}
	return nil
}

func (m *VirtualMachineProfile) GetOs() *OperatingSystemConfiguration {
	if m != nil {
		return m.Os
	}
	return nil
}

func (m *VirtualMachineProfile) GetHardware() *HardwareConfiguration {
	if m != nil {
		return m.Hardware
	}
	return nil
}

func (m *VirtualMachineProfile) GetSecurity() *SecurityConfiguration {
	if m != nil {
		return m.Security
	}
	return nil
}

func (m *VirtualMachineProfile) GetGuestAgent() *common.GuestAgentConfiguration {
	if m != nil {
		return m.GuestAgent
	}
	return nil
}

type VirtualMachineScaleSet struct {
	Name                    string                       `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                      string                       `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Sku                     *Sku                         `protobuf:"bytes,3,opt,name=sku,proto3" json:"sku,omitempty"`
	Virtualmachineprofile   *VirtualMachineProfile       `protobuf:"bytes,4,opt,name=virtualmachineprofile,proto3" json:"virtualmachineprofile,omitempty"`
	VirtualMachineSystems   []*VirtualMachine            `protobuf:"bytes,5,rep,name=VirtualMachineSystems,proto3" json:"VirtualMachineSystems,omitempty"`
	Status                  *common.Status               `protobuf:"bytes,7,opt,name=status,proto3" json:"status,omitempty"`
	DisableHighAvailability bool                         `protobuf:"varint,8,opt,name=DisableHighAvailability,proto3" json:"DisableHighAvailability,omitempty"`
	AllowedOwnerNodes       []string                     `protobuf:"bytes,9,rep,name=allowedOwnerNodes,proto3" json:"allowedOwnerNodes,omitempty"`
	Entity                  *common.Entity               `protobuf:"bytes,10,opt,name=entity,proto3" json:"entity,omitempty"`
	HighAvailabilityState   common.HighAvailabilityState `protobuf:"varint,11,opt,name=highAvailabilityState,proto3,enum=moc.HighAvailabilityState" json:"highAvailabilityState,omitempty"`
	Tags                    *common.Tags                 `protobuf:"bytes,12,opt,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral    struct{}                     `json:"-"`
	XXX_unrecognized        []byte                       `json:"-"`
	XXX_sizecache           int32                        `json:"-"`
}

func (m *VirtualMachineScaleSet) Reset()         { *m = VirtualMachineScaleSet{} }
func (m *VirtualMachineScaleSet) String() string { return proto.CompactTextString(m) }
func (*VirtualMachineScaleSet) ProtoMessage()    {}
func (*VirtualMachineScaleSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_c094179683a8aea5, []int{5}
}

func (m *VirtualMachineScaleSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualMachineScaleSet.Unmarshal(m, b)
}
func (m *VirtualMachineScaleSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualMachineScaleSet.Marshal(b, m, deterministic)
}
func (m *VirtualMachineScaleSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualMachineScaleSet.Merge(m, src)
}
func (m *VirtualMachineScaleSet) XXX_Size() int {
	return xxx_messageInfo_VirtualMachineScaleSet.Size(m)
}
func (m *VirtualMachineScaleSet) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualMachineScaleSet.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualMachineScaleSet proto.InternalMessageInfo

func (m *VirtualMachineScaleSet) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *VirtualMachineScaleSet) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *VirtualMachineScaleSet) GetSku() *Sku {
	if m != nil {
		return m.Sku
	}
	return nil
}

func (m *VirtualMachineScaleSet) GetVirtualmachineprofile() *VirtualMachineProfile {
	if m != nil {
		return m.Virtualmachineprofile
	}
	return nil
}

func (m *VirtualMachineScaleSet) GetVirtualMachineSystems() []*VirtualMachine {
	if m != nil {
		return m.VirtualMachineSystems
	}
	return nil
}

func (m *VirtualMachineScaleSet) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *VirtualMachineScaleSet) GetDisableHighAvailability() bool {
	if m != nil {
		return m.DisableHighAvailability
	}
	return false
}

func (m *VirtualMachineScaleSet) GetAllowedOwnerNodes() []string {
	if m != nil {
		return m.AllowedOwnerNodes
	}
	return nil
}

func (m *VirtualMachineScaleSet) GetEntity() *common.Entity {
	if m != nil {
		return m.Entity
	}
	return nil
}

func (m *VirtualMachineScaleSet) GetHighAvailabilityState() common.HighAvailabilityState {
	if m != nil {
		return m.HighAvailabilityState
	}
	return common.HighAvailabilityState_UNKNOWN_HA_STATE
}

func (m *VirtualMachineScaleSet) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func init() {
	proto.RegisterType((*VirtualMachineScaleSetRequest)(nil), "moc.nodeagent.compute.VirtualMachineScaleSetRequest")
	proto.RegisterType((*VirtualMachineScaleSetResponse)(nil), "moc.nodeagent.compute.VirtualMachineScaleSetResponse")
	proto.RegisterType((*Sku)(nil), "moc.nodeagent.compute.Sku")
	proto.RegisterType((*NetworkConfigurationScaleSet)(nil), "moc.nodeagent.compute.NetworkConfigurationScaleSet")
	proto.RegisterType((*VirtualMachineProfile)(nil), "moc.nodeagent.compute.VirtualMachineProfile")
	proto.RegisterType((*VirtualMachineScaleSet)(nil), "moc.nodeagent.compute.VirtualMachineScaleSet")
}

func init() {
	proto.RegisterFile("moc_nodeagent_virtualmachinescaleset.proto", fileDescriptor_c094179683a8aea5)
}

var fileDescriptor_c094179683a8aea5 = []byte{
	// 780 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xc4, 0x95, 0x4d, 0x6f, 0xda, 0x48,
	0x18, 0xc7, 0xd7, 0x40, 0x08, 0x0c, 0xbb, 0x91, 0x76, 0xb4, 0x6c, 0x2c, 0x36, 0x89, 0x90, 0x57,
	0x2b, 0xa1, 0x0d, 0x6b, 0x56, 0x24, 0x91, 0x7a, 0xe8, 0x25, 0x49, 0xa3, 0x92, 0x43, 0x5e, 0x34,
	0x44, 0x39, 0xb4, 0x87, 0x68, 0x30, 0x83, 0x19, 0x61, 0x7b, 0xdc, 0x99, 0x31, 0x34, 0x5f, 0xa4,
	0x1f, 0xaa, 0x87, 0x7e, 0x85, 0xf6, 0xa3, 0x54, 0x1e, 0x8f, 0xad, 0x98, 0xda, 0x28, 0x39, 0xf5,
	0x04, 0x9e, 0xe7, 0xff, 0xfc, 0x9e, 0x57, 0x8f, 0xc1, 0xbf, 0x3e, 0x73, 0x1e, 0x02, 0x36, 0x25,
	0xd8, 0x25, 0x81, 0x7c, 0x58, 0x52, 0x2e, 0x23, 0xec, 0xf9, 0xd8, 0x99, 0xd3, 0x80, 0x08, 0x07,
	0x7b, 0x44, 0x10, 0x69, 0x87, 0x9c, 0x49, 0x06, 0xdb, 0x3e, 0x73, 0xec, 0x4c, 0x6b, 0x3b, 0xcc,
	0x0f, 0x23, 0x49, 0x3a, 0x07, 0x2e, 0x63, 0xae, 0x47, 0x06, 0x4a, 0x34, 0x89, 0x66, 0x83, 0x15,
	0xc7, 0x61, 0x48, 0xb8, 0x48, 0xdc, 0x3a, 0xd6, 0xa6, 0x10, 0x5a, 0xb3, 0x1b, 0x6b, 0x1c, 0xe6,
	0xfb, 0x2c, 0xd0, 0x3f, 0xda, 0x70, 0x90, 0x37, 0xc4, 0x01, 0x73, 0xf6, 0xc3, 0x42, 0x78, 0x40,
	0xe4, 0x8a, 0xf1, 0x05, 0x0d, 0x24, 0xe1, 0x33, 0xec, 0xe8, 0x28, 0xd6, 0x67, 0x03, 0xec, 0xdf,
	0x27, 0x8a, 0xab, 0x24, 0xfc, 0x38, 0xae, 0x70, 0x4c, 0x24, 0x22, 0x1f, 0x22, 0x22, 0x24, 0x14,
	0x65, 0x82, 0xf1, 0xa3, 0x90, 0xc4, 0x17, 0xa6, 0xd1, 0xad, 0xf6, 0x5a, 0xc3, 0xff, 0xec, 0xc2,
	0x56, 0xd8, 0x25, 0xf0, 0xcd, 0x4c, 0x78, 0x0c, 0x7e, 0xbb, 0x09, 0x09, 0xc7, 0x92, 0xb2, 0xe0,
	0xee, 0x31, 0x24, 0x66, 0xa5, 0x6b, 0xf4, 0x76, 0x86, 0x3b, 0x2a, 0x48, 0x66, 0x41, 0x79, 0x91,
	0xf5, 0xd5, 0x00, 0x07, 0x65, 0xc5, 0x88, 0x90, 0x05, 0x82, 0xfc, 0x9c, 0x6a, 0x86, 0xa0, 0x8e,
	0x88, 0x88, 0x3c, 0xa9, 0xca, 0x68, 0x0d, 0x3b, 0x76, 0xb2, 0x1f, 0x76, 0xba, 0x1f, 0xf6, 0x19,
	0x63, 0xde, 0x3d, 0xf6, 0x22, 0x82, 0xb4, 0x12, 0xfe, 0x01, 0xb6, 0x2e, 0x38, 0x67, 0xdc, 0xac,
	0x76, 0x8d, 0x5e, 0x13, 0x25, 0x0f, 0xd6, 0x09, 0xa8, 0x8e, 0x17, 0x11, 0x84, 0xa0, 0x16, 0x60,
	0x9f, 0x98, 0x86, 0xb2, 0xa9, 0xff, 0xb0, 0x03, 0x1a, 0x0e, 0x0e, 0xb1, 0x43, 0xe5, 0xa3, 0x0a,
	0x53, 0x45, 0xd9, 0xb3, 0x15, 0x80, 0xbd, 0xeb, 0x64, 0xfe, 0xe7, 0x2c, 0x98, 0x51, 0x37, 0x4a,
	0x9a, 0x96, 0xe6, 0x09, 0xaf, 0x01, 0xc8, 0x16, 0x23, 0x6d, 0x81, 0xbd, 0xd6, 0x02, 0xbd, 0x40,
	0x69, 0x0b, 0x34, 0xef, 0x32, 0x75, 0x43, 0x4f, 0x08, 0xd6, 0xb7, 0x2a, 0x68, 0xe7, 0x5b, 0x72,
	0xcb, 0xd9, 0x8c, 0x7a, 0x2a, 0xcb, 0xa5, 0x1f, 0x72, 0x32, 0xa3, 0x1f, 0x75, 0xf6, 0xd9, 0x33,
	0xbc, 0x02, 0xdb, 0x3a, 0x88, 0xee, 0xd3, 0x51, 0xc9, 0x14, 0x36, 0xd5, 0x82, 0x52, 0x06, 0xbc,
	0x00, 0xdb, 0x42, 0x32, 0x8e, 0x5d, 0xa2, 0x7a, 0xd8, 0x1a, 0x1e, 0x96, 0xe0, 0xc6, 0x89, 0x2a,
	0x87, 0x43, 0xa9, 0x2f, 0x3c, 0x07, 0x15, 0x26, 0xcc, 0xda, 0xc6, 0x84, 0xf4, 0x1a, 0x06, 0x6e,
	0x32, 0xf1, 0x3c, 0xa9, 0xc2, 0x04, 0x1c, 0x81, 0xc6, 0x1c, 0xf3, 0xe9, 0x0a, 0x73, 0x62, 0x6e,
	0x29, 0x54, 0xbf, 0x04, 0x35, 0xd2, 0xb2, 0x3c, 0x23, 0xf3, 0x8e, 0x49, 0x82, 0x38, 0x11, 0x8f,
	0xc7, 0x5c, 0xdf, 0x48, 0x1a, 0x6b, 0xd9, 0x1a, 0x29, 0xf5, 0x86, 0xaf, 0x01, 0x70, 0xe3, 0x37,
	0xfc, 0x34, 0xf6, 0x32, 0xb7, 0x15, 0x6b, 0x4f, 0xb1, 0xde, 0x66, 0xc7, 0x79, 0xdf, 0x27, 0x7a,
	0xeb, 0x4b, 0x0d, 0xfc, 0x59, 0xbc, 0xf5, 0x85, 0xdb, 0xb9, 0x03, 0x2a, 0x74, 0xaa, 0xc6, 0xda,
	0x44, 0x15, 0x3a, 0x85, 0x7d, 0x50, 0x15, 0x8b, 0x48, 0x0f, 0xa6, 0x53, 0x56, 0xc1, 0x22, 0x42,
	0xb1, 0x0c, 0x4e, 0x40, 0x3b, 0x7f, 0x47, 0x86, 0xc9, 0x3a, 0xe9, 0xb1, 0xf4, 0x9f, 0xf5, 0xb6,
	0xea, 0x15, 0x44, 0xc5, 0x28, 0xf8, 0x7e, 0x7d, 0x65, 0xd3, 0x1b, 0x61, 0x4b, 0xbd, 0x0e, 0xff,
	0x3c, 0x2b, 0x06, 0x2a, 0x66, 0xc0, 0xbf, 0x41, 0x5d, 0x48, 0x2c, 0x23, 0xa1, 0xfb, 0xdc, 0x52,
	0xb4, 0xb1, 0x3a, 0x42, 0xda, 0x04, 0x5f, 0x81, 0xdd, 0x37, 0x54, 0xe0, 0x89, 0x47, 0x46, 0xd4,
	0x9d, 0x9f, 0x2e, 0x31, 0xf5, 0xf0, 0x84, 0x7a, 0xf1, 0xa4, 0x1b, 0x5d, 0xa3, 0xd7, 0x40, 0x65,
	0x66, 0xd8, 0x07, 0xbf, 0x63, 0xcf, 0x63, 0x2b, 0x32, 0xbd, 0x59, 0x05, 0x84, 0x5f, 0xb3, 0x29,
	0x11, 0x66, 0xb3, 0x5b, 0xed, 0x35, 0xd1, 0x8f, 0x86, 0x38, 0x19, 0x12, 0xc8, 0x18, 0x0b, 0x9e,
	0x24, 0x73, 0xa1, 0x8e, 0x90, 0x36, 0xc1, 0x5b, 0xd0, 0x9e, 0xaf, 0x85, 0x89, 0xd3, 0x25, 0x66,
	0x4b, 0xdd, 0xc4, 0xc9, 0xc8, 0x46, 0x45, 0x0a, 0x54, 0xec, 0x08, 0xf7, 0x41, 0x4d, 0x62, 0x57,
	0x98, 0xbf, 0xaa, 0xa0, 0x4d, 0x05, 0xb8, 0xc3, 0xae, 0x40, 0xea, 0x78, 0xf8, 0xc9, 0x00, 0x7f,
	0x15, 0x2f, 0x94, 0x5a, 0x38, 0xb8, 0x02, 0xf5, 0xcb, 0x60, 0xc9, 0x16, 0x04, 0x1e, 0xbf, 0xec,
	0x72, 0x4e, 0xbe, 0x63, 0x9d, 0x93, 0x17, 0x7a, 0x25, 0x1f, 0x0c, 0xeb, 0x97, 0xb3, 0xff, 0xdf,
	0xd9, 0x2e, 0x95, 0xf3, 0x68, 0x12, 0xbb, 0x0c, 0x7c, 0xea, 0x70, 0x26, 0xd8, 0x4c, 0x0e, 0x7c,
	0xe6, 0x0c, 0x78, 0xe8, 0x0c, 0x32, 0xe4, 0x40, 0x23, 0x27, 0x75, 0x75, 0xaf, 0x1f, 0x7d, 0x0f,
	0x00, 0x00, 0xff, 0xff, 0xf3, 0x63, 0x5a, 0x03, 0x4a, 0x08, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// VirtualMachineScaleSetAgentClient is the client API for VirtualMachineScaleSetAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type VirtualMachineScaleSetAgentClient interface {
	Invoke(ctx context.Context, in *VirtualMachineScaleSetRequest, opts ...grpc.CallOption) (*VirtualMachineScaleSetResponse, error)
}

type virtualMachineScaleSetAgentClient struct {
	cc *grpc.ClientConn
}

func NewVirtualMachineScaleSetAgentClient(cc *grpc.ClientConn) VirtualMachineScaleSetAgentClient {
	return &virtualMachineScaleSetAgentClient{cc}
}

func (c *virtualMachineScaleSetAgentClient) Invoke(ctx context.Context, in *VirtualMachineScaleSetRequest, opts ...grpc.CallOption) (*VirtualMachineScaleSetResponse, error) {
	out := new(VirtualMachineScaleSetResponse)
	err := c.cc.Invoke(ctx, "/moc.nodeagent.compute.VirtualMachineScaleSetAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VirtualMachineScaleSetAgentServer is the server API for VirtualMachineScaleSetAgent service.
type VirtualMachineScaleSetAgentServer interface {
	Invoke(context.Context, *VirtualMachineScaleSetRequest) (*VirtualMachineScaleSetResponse, error)
}

// UnimplementedVirtualMachineScaleSetAgentServer can be embedded to have forward compatible implementations.
type UnimplementedVirtualMachineScaleSetAgentServer struct {
}

func (*UnimplementedVirtualMachineScaleSetAgentServer) Invoke(ctx context.Context, req *VirtualMachineScaleSetRequest) (*VirtualMachineScaleSetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}

func RegisterVirtualMachineScaleSetAgentServer(s *grpc.Server, srv VirtualMachineScaleSetAgentServer) {
	s.RegisterService(&_VirtualMachineScaleSetAgent_serviceDesc, srv)
}

func _VirtualMachineScaleSetAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VirtualMachineScaleSetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VirtualMachineScaleSetAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.nodeagent.compute.VirtualMachineScaleSetAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VirtualMachineScaleSetAgentServer).Invoke(ctx, req.(*VirtualMachineScaleSetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _VirtualMachineScaleSetAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.nodeagent.compute.VirtualMachineScaleSetAgent",
	HandlerType: (*VirtualMachineScaleSetAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _VirtualMachineScaleSetAgent_Invoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_nodeagent_virtualmachinescaleset.proto",
}
