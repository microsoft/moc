// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_availabilityset.proto

package compute

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	common "github.com/microsoft/moc/rpc/common"
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

type AvailabilitySetRequest struct {
	AvailabilitySets     []*AvailabilitySet `protobuf:"bytes,1,rep,name=AvailabilitySets,proto3" json:"AvailabilitySets,omitempty"`
	OperationType        common.Operation   `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *AvailabilitySetRequest) Reset()         { *m = AvailabilitySetRequest{} }
func (m *AvailabilitySetRequest) String() string { return proto.CompactTextString(m) }
func (*AvailabilitySetRequest) ProtoMessage()    {}
func (*AvailabilitySetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f2024bad12ef389f, []int{0}
}

func (m *AvailabilitySetRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AvailabilitySetRequest.Unmarshal(m, b)
}
func (m *AvailabilitySetRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AvailabilitySetRequest.Marshal(b, m, deterministic)
}
func (m *AvailabilitySetRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AvailabilitySetRequest.Merge(m, src)
}
func (m *AvailabilitySetRequest) XXX_Size() int {
	return xxx_messageInfo_AvailabilitySetRequest.Size(m)
}
func (m *AvailabilitySetRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AvailabilitySetRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AvailabilitySetRequest proto.InternalMessageInfo

func (m *AvailabilitySetRequest) GetAvailabilitySets() []*AvailabilitySet {
	if m != nil {
		return m.AvailabilitySets
	}
	return nil
}

func (m *AvailabilitySetRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type AvailabilitySetResponse struct {
	AvailabilitySets     []*AvailabilitySet  `protobuf:"bytes,1,rep,name=AvailabilitySets,proto3" json:"AvailabilitySets,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *AvailabilitySetResponse) Reset()         { *m = AvailabilitySetResponse{} }
func (m *AvailabilitySetResponse) String() string { return proto.CompactTextString(m) }
func (*AvailabilitySetResponse) ProtoMessage()    {}
func (*AvailabilitySetResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_f2024bad12ef389f, []int{1}
}

func (m *AvailabilitySetResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AvailabilitySetResponse.Unmarshal(m, b)
}
func (m *AvailabilitySetResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AvailabilitySetResponse.Marshal(b, m, deterministic)
}
func (m *AvailabilitySetResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AvailabilitySetResponse.Merge(m, src)
}
func (m *AvailabilitySetResponse) XXX_Size() int {
	return xxx_messageInfo_AvailabilitySetResponse.Size(m)
}
func (m *AvailabilitySetResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AvailabilitySetResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AvailabilitySetResponse proto.InternalMessageInfo

func (m *AvailabilitySetResponse) GetAvailabilitySets() []*AvailabilitySet {
	if m != nil {
		return m.AvailabilitySets
	}
	return nil
}

func (m *AvailabilitySetResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *AvailabilitySetResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type VirtualMachineReference struct {
	GroupName            string   `protobuf:"bytes,1,opt,name=groupName,proto3" json:"groupName,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	RealizedName         string   `protobuf:"bytes,3,opt,name=realizedName,proto3" json:"realizedName,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VirtualMachineReference) Reset()         { *m = VirtualMachineReference{} }
func (m *VirtualMachineReference) String() string { return proto.CompactTextString(m) }
func (*VirtualMachineReference) ProtoMessage()    {}
func (*VirtualMachineReference) Descriptor() ([]byte, []int) {
	return fileDescriptor_f2024bad12ef389f, []int{2}
}

func (m *VirtualMachineReference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualMachineReference.Unmarshal(m, b)
}
func (m *VirtualMachineReference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualMachineReference.Marshal(b, m, deterministic)
}
func (m *VirtualMachineReference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualMachineReference.Merge(m, src)
}
func (m *VirtualMachineReference) XXX_Size() int {
	return xxx_messageInfo_VirtualMachineReference.Size(m)
}
func (m *VirtualMachineReference) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualMachineReference.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualMachineReference proto.InternalMessageInfo

func (m *VirtualMachineReference) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *VirtualMachineReference) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *VirtualMachineReference) GetRealizedName() string {
	if m != nil {
		return m.RealizedName
	}
	return ""
}

type AvailabilitySetPrecheckRequest struct {
	AvailabilitySets     []*AvailabilitySet `protobuf:"bytes,1,rep,name=AvailabilitySets,proto3" json:"AvailabilitySets,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *AvailabilitySetPrecheckRequest) Reset()         { *m = AvailabilitySetPrecheckRequest{} }
func (m *AvailabilitySetPrecheckRequest) String() string { return proto.CompactTextString(m) }
func (*AvailabilitySetPrecheckRequest) ProtoMessage()    {}
func (*AvailabilitySetPrecheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f2024bad12ef389f, []int{3}
}

func (m *AvailabilitySetPrecheckRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AvailabilitySetPrecheckRequest.Unmarshal(m, b)
}
func (m *AvailabilitySetPrecheckRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AvailabilitySetPrecheckRequest.Marshal(b, m, deterministic)
}
func (m *AvailabilitySetPrecheckRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AvailabilitySetPrecheckRequest.Merge(m, src)
}
func (m *AvailabilitySetPrecheckRequest) XXX_Size() int {
	return xxx_messageInfo_AvailabilitySetPrecheckRequest.Size(m)
}
func (m *AvailabilitySetPrecheckRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AvailabilitySetPrecheckRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AvailabilitySetPrecheckRequest proto.InternalMessageInfo

func (m *AvailabilitySetPrecheckRequest) GetAvailabilitySets() []*AvailabilitySet {
	if m != nil {
		return m.AvailabilitySets
	}
	return nil
}

type AvailabilitySetPrecheckResponse struct {
	// The precheck result: true if the precheck criteria is passed; otherwise, false
	Result *wrappers.BoolValue `protobuf:"bytes,1,opt,name=Result,proto3" json:"Result,omitempty"`
	// The error message if the precheck is not passed; otherwise, empty string
	Error                string   `protobuf:"bytes,2,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AvailabilitySetPrecheckResponse) Reset()         { *m = AvailabilitySetPrecheckResponse{} }
func (m *AvailabilitySetPrecheckResponse) String() string { return proto.CompactTextString(m) }
func (*AvailabilitySetPrecheckResponse) ProtoMessage()    {}
func (*AvailabilitySetPrecheckResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_f2024bad12ef389f, []int{4}
}

func (m *AvailabilitySetPrecheckResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AvailabilitySetPrecheckResponse.Unmarshal(m, b)
}
func (m *AvailabilitySetPrecheckResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AvailabilitySetPrecheckResponse.Marshal(b, m, deterministic)
}
func (m *AvailabilitySetPrecheckResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AvailabilitySetPrecheckResponse.Merge(m, src)
}
func (m *AvailabilitySetPrecheckResponse) XXX_Size() int {
	return xxx_messageInfo_AvailabilitySetPrecheckResponse.Size(m)
}
func (m *AvailabilitySetPrecheckResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AvailabilitySetPrecheckResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AvailabilitySetPrecheckResponse proto.InternalMessageInfo

func (m *AvailabilitySetPrecheckResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *AvailabilitySetPrecheckResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

// avset structure is a flattened version of the model in the Azure sdk for go at
// https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/resourcemanager/compute/armcompute/models.go
type AvailabilitySet struct {
	Name                     string                     `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                       string                     `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	LocationName             string                     `protobuf:"bytes,3,opt,name=locationName,proto3" json:"locationName,omitempty"`
	GroupName                string                     `protobuf:"bytes,4,opt,name=groupName,proto3" json:"groupName,omitempty"`
	Status                   *common.Status             `protobuf:"bytes,5,opt,name=status,proto3" json:"status,omitempty"`
	Tags                     *common.Tags               `protobuf:"bytes,6,opt,name=tags,proto3" json:"tags,omitempty"`
	PlatformFaultDomainCount int32                      `protobuf:"varint,7,opt,name=platformFaultDomainCount,proto3" json:"platformFaultDomainCount,omitempty"`
	VirtualMachines          []*VirtualMachineReference `protobuf:"bytes,8,rep,name=virtualMachines,proto3" json:"virtualMachines,omitempty"`
	XXX_NoUnkeyedLiteral     struct{}                   `json:"-"`
	XXX_unrecognized         []byte                     `json:"-"`
	XXX_sizecache            int32                      `json:"-"`
}

func (m *AvailabilitySet) Reset()         { *m = AvailabilitySet{} }
func (m *AvailabilitySet) String() string { return proto.CompactTextString(m) }
func (*AvailabilitySet) ProtoMessage()    {}
func (*AvailabilitySet) Descriptor() ([]byte, []int) {
	return fileDescriptor_f2024bad12ef389f, []int{5}
}

func (m *AvailabilitySet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AvailabilitySet.Unmarshal(m, b)
}
func (m *AvailabilitySet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AvailabilitySet.Marshal(b, m, deterministic)
}
func (m *AvailabilitySet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AvailabilitySet.Merge(m, src)
}
func (m *AvailabilitySet) XXX_Size() int {
	return xxx_messageInfo_AvailabilitySet.Size(m)
}
func (m *AvailabilitySet) XXX_DiscardUnknown() {
	xxx_messageInfo_AvailabilitySet.DiscardUnknown(m)
}

var xxx_messageInfo_AvailabilitySet proto.InternalMessageInfo

func (m *AvailabilitySet) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *AvailabilitySet) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *AvailabilitySet) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *AvailabilitySet) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *AvailabilitySet) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *AvailabilitySet) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func (m *AvailabilitySet) GetPlatformFaultDomainCount() int32 {
	if m != nil {
		return m.PlatformFaultDomainCount
	}
	return 0
}

func (m *AvailabilitySet) GetVirtualMachines() []*VirtualMachineReference {
	if m != nil {
		return m.VirtualMachines
	}
	return nil
}

func init() {
	proto.RegisterType((*AvailabilitySetRequest)(nil), "moc.cloudagent.compute.AvailabilitySetRequest")
	proto.RegisterType((*AvailabilitySetResponse)(nil), "moc.cloudagent.compute.AvailabilitySetResponse")
	proto.RegisterType((*VirtualMachineReference)(nil), "moc.cloudagent.compute.VirtualMachineReference")
	proto.RegisterType((*AvailabilitySetPrecheckRequest)(nil), "moc.cloudagent.compute.AvailabilitySetPrecheckRequest")
	proto.RegisterType((*AvailabilitySetPrecheckResponse)(nil), "moc.cloudagent.compute.AvailabilitySetPrecheckResponse")
	proto.RegisterType((*AvailabilitySet)(nil), "moc.cloudagent.compute.AvailabilitySet")
}

func init() {
	proto.RegisterFile("moc_cloudagent_availabilityset.proto", fileDescriptor_f2024bad12ef389f)
}

var fileDescriptor_f2024bad12ef389f = []byte{
	// 560 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x52, 0x4d, 0x6f, 0xd3, 0x40,
	0x10, 0xc5, 0x6e, 0x1b, 0xda, 0x2d, 0xb4, 0x68, 0x55, 0x35, 0x56, 0x04, 0x25, 0x32, 0x48, 0xe4,
	0x64, 0x8b, 0x80, 0x40, 0xe2, 0xd6, 0xf2, 0x21, 0x71, 0xe0, 0x43, 0x4e, 0x55, 0x09, 0x2e, 0xd5,
	0x66, 0x33, 0x71, 0x56, 0x59, 0x7b, 0xcc, 0x7e, 0x04, 0x15, 0x89, 0x0b, 0x7f, 0x85, 0x3f, 0xc1,
	0xef, 0xe0, 0x17, 0xa1, 0xac, 0x9d, 0x26, 0x71, 0x89, 0x94, 0x1e, 0x7a, 0x4a, 0x3c, 0xf3, 0xde,
	0x9b, 0xd9, 0x37, 0x8f, 0x3c, 0xce, 0x90, 0x9f, 0x73, 0x89, 0x76, 0xc0, 0x52, 0xc8, 0xcd, 0x39,
	0x9b, 0x30, 0x21, 0x59, 0x5f, 0x48, 0x61, 0x2e, 0x34, 0x98, 0xa8, 0x50, 0x68, 0x90, 0x1e, 0x66,
	0xc8, 0xa3, 0x39, 0x2a, 0xe2, 0x98, 0x15, 0xd6, 0x40, 0xeb, 0x28, 0x45, 0x4c, 0x25, 0xc4, 0x0e,
	0xd5, 0xb7, 0xc3, 0xf8, 0xbb, 0x62, 0x45, 0x01, 0x4a, 0x97, 0xbc, 0x56, 0xd3, 0xa9, 0x63, 0x96,
	0x61, 0x5e, 0xfd, 0x94, 0x8d, 0xf0, 0xb7, 0x47, 0x0e, 0x8f, 0x17, 0x46, 0xf5, 0xc0, 0x24, 0xf0,
	0xcd, 0x82, 0x36, 0xb4, 0x47, 0xee, 0xd5, 0x3a, 0x3a, 0xf0, 0xda, 0x1b, 0x9d, 0xdd, 0xee, 0x93,
	0xe8, 0xff, 0x6b, 0x44, 0x75, 0xa5, 0x2b, 0x02, 0xf4, 0x39, 0xb9, 0xfb, 0xa9, 0x00, 0xc5, 0x8c,
	0xc0, 0xfc, 0xf4, 0xa2, 0x80, 0xc0, 0x6f, 0x7b, 0x9d, 0xbd, 0xee, 0x9e, 0x53, 0xbc, 0xec, 0x24,
	0xcb, 0xa0, 0xf0, 0x8f, 0x47, 0x9a, 0x57, 0xb6, 0xd4, 0x05, 0xe6, 0x1a, 0x6e, 0x66, 0xcd, 0x2e,
	0x69, 0x24, 0xa0, 0xad, 0x34, 0x6e, 0xbf, 0xdd, 0x6e, 0x2b, 0x2a, 0x0d, 0x8e, 0x66, 0x06, 0x47,
	0x27, 0x88, 0xf2, 0x8c, 0x49, 0x0b, 0x49, 0x85, 0xa4, 0x07, 0x64, 0xeb, 0xad, 0x52, 0xa8, 0x82,
	0x8d, 0xb6, 0xd7, 0xd9, 0x49, 0xca, 0x8f, 0x10, 0x49, 0xf3, 0x4c, 0x28, 0x63, 0x99, 0xfc, 0xc0,
	0xf8, 0x48, 0xe4, 0x90, 0xc0, 0x10, 0x14, 0xe4, 0x1c, 0xe8, 0x7d, 0xb2, 0x93, 0x2a, 0xb4, 0xc5,
	0x47, 0x96, 0x41, 0xe0, 0x39, 0xd2, 0xbc, 0x40, 0x29, 0xd9, 0xcc, 0xa7, 0x0d, 0xdf, 0x35, 0xdc,
	0x7f, 0x1a, 0x92, 0x3b, 0x0a, 0x98, 0x14, 0x3f, 0x60, 0xe0, 0x48, 0xe5, 0xa4, 0xa5, 0x5a, 0x68,
	0xc9, 0x51, 0xed, 0x39, 0x9f, 0x15, 0xf0, 0x11, 0xf0, 0xf1, 0x4d, 0x1e, 0x36, 0x1c, 0x93, 0x87,
	0x2b, 0xc7, 0x56, 0x97, 0x9a, 0x9b, 0xea, 0x5d, 0xdf, 0x54, 0x7f, 0xd1, 0xd4, 0xbf, 0x3e, 0xd9,
	0xaf, 0x4d, 0xbb, 0xf4, 0xcb, 0x5b, 0xf0, 0x6b, 0x8f, 0xf8, 0x62, 0x50, 0x51, 0x7d, 0x31, 0x98,
	0xfa, 0x27, 0x91, 0xbb, 0x5c, 0x2d, 0xfa, 0xb7, 0x58, 0x5b, 0xbe, 0xca, 0x66, 0xfd, 0x2a, 0x8f,
	0x48, 0x43, 0x1b, 0x66, 0xac, 0x0e, 0xb6, 0xdc, 0x1b, 0x76, 0x9d, 0x63, 0x3d, 0x57, 0x4a, 0xaa,
	0x16, 0x7d, 0x40, 0x36, 0x0d, 0x4b, 0x75, 0xd0, 0x70, 0x90, 0x1d, 0x07, 0x39, 0x65, 0xa9, 0x4e,
	0x5c, 0x99, 0xbe, 0x22, 0x41, 0x21, 0x99, 0x19, 0xa2, 0xca, 0xde, 0x31, 0x2b, 0xcd, 0x1b, 0xcc,
	0x98, 0xc8, 0x5f, 0xa3, 0xcd, 0x4d, 0x70, 0xbb, 0xed, 0x75, 0xb6, 0x92, 0x95, 0x7d, 0xfa, 0x85,
	0xec, 0x4f, 0x96, 0xe2, 0xa4, 0x83, 0x6d, 0x77, 0xba, 0x78, 0xd5, 0xe9, 0x56, 0xa4, 0x2f, 0xa9,
	0xeb, 0x74, 0x7f, 0xf9, 0xe4, 0xa0, 0x66, 0xea, 0xf1, 0x54, 0x89, 0x8e, 0x49, 0xe3, 0x7d, 0x3e,
	0xc1, 0x31, 0xd0, 0x68, 0xdd, 0x7c, 0x94, 0x49, 0x6b, 0xc5, 0x6b, 0xe3, 0xcb, 0x88, 0x84, 0xb7,
	0xe8, 0x4f, 0xb2, 0x3d, 0x0b, 0x0e, 0x7d, 0xb1, 0x26, 0xbd, 0x16, 0xf0, 0xd6, 0xcb, 0x6b, 0xf3,
	0x66, 0xe3, 0x4f, 0x9e, 0x7e, 0x8d, 0x53, 0x61, 0x46, 0xb6, 0x3f, 0xe5, 0xc4, 0x99, 0xe0, 0x0a,
	0x35, 0x0e, 0x4d, 0x9c, 0x21, 0x8f, 0x55, 0xc1, 0xe3, 0xb9, 0x68, 0x5c, 0x89, 0xf6, 0x1b, 0x2e,
	0xbe, 0xcf, 0xfe, 0x05, 0x00, 0x00, 0xff, 0xff, 0x1b, 0x14, 0x16, 0x9f, 0xc2, 0x05, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AvailabilitySetAgentClient is the client API for AvailabilitySetAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AvailabilitySetAgentClient interface {
	Invoke(ctx context.Context, in *AvailabilitySetRequest, opts ...grpc.CallOption) (*AvailabilitySetResponse, error)
	// Prechecks whether the system is able to create specified availability set (but does not actually create them).
	Precheck(ctx context.Context, in *AvailabilitySetPrecheckRequest, opts ...grpc.CallOption) (*AvailabilitySetPrecheckResponse, error)
}

type availabilitySetAgentClient struct {
	cc *grpc.ClientConn
}

func NewAvailabilitySetAgentClient(cc *grpc.ClientConn) AvailabilitySetAgentClient {
	return &availabilitySetAgentClient{cc}
}

func (c *availabilitySetAgentClient) Invoke(ctx context.Context, in *AvailabilitySetRequest, opts ...grpc.CallOption) (*AvailabilitySetResponse, error) {
	out := new(AvailabilitySetResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.compute.AvailabilitySetAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *availabilitySetAgentClient) Precheck(ctx context.Context, in *AvailabilitySetPrecheckRequest, opts ...grpc.CallOption) (*AvailabilitySetPrecheckResponse, error) {
	out := new(AvailabilitySetPrecheckResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.compute.AvailabilitySetAgent/Precheck", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AvailabilitySetAgentServer is the server API for AvailabilitySetAgent service.
type AvailabilitySetAgentServer interface {
	Invoke(context.Context, *AvailabilitySetRequest) (*AvailabilitySetResponse, error)
	// Prechecks whether the system is able to create specified availability set (but does not actually create them).
	Precheck(context.Context, *AvailabilitySetPrecheckRequest) (*AvailabilitySetPrecheckResponse, error)
}

// UnimplementedAvailabilitySetAgentServer can be embedded to have forward compatible implementations.
type UnimplementedAvailabilitySetAgentServer struct {
}

func (*UnimplementedAvailabilitySetAgentServer) Invoke(ctx context.Context, req *AvailabilitySetRequest) (*AvailabilitySetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}
func (*UnimplementedAvailabilitySetAgentServer) Precheck(ctx context.Context, req *AvailabilitySetPrecheckRequest) (*AvailabilitySetPrecheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Precheck not implemented")
}

func RegisterAvailabilitySetAgentServer(s *grpc.Server, srv AvailabilitySetAgentServer) {
	s.RegisterService(&_AvailabilitySetAgent_serviceDesc, srv)
}

func _AvailabilitySetAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AvailabilitySetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AvailabilitySetAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.compute.AvailabilitySetAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AvailabilitySetAgentServer).Invoke(ctx, req.(*AvailabilitySetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AvailabilitySetAgent_Precheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AvailabilitySetPrecheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AvailabilitySetAgentServer).Precheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.compute.AvailabilitySetAgent/Precheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AvailabilitySetAgentServer).Precheck(ctx, req.(*AvailabilitySetPrecheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AvailabilitySetAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.compute.AvailabilitySetAgent",
	HandlerType: (*AvailabilitySetAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _AvailabilitySetAgent_Invoke_Handler,
		},
		{
			MethodName: "Precheck",
			Handler:    _AvailabilitySetAgent_Precheck_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_availabilityset.proto",
}
