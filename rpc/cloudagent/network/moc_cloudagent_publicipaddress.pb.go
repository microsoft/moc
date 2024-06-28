// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_publicipaddress.proto

package network

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

type PublicIPAddressRequest struct {
	PublicIPAddresses    []*PublicIPAddress `protobuf:"bytes,1,rep,name=PublicIPAddresses,proto3" json:"PublicIPAddresses,omitempty"`
	OperationType        common.Operation   `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *PublicIPAddressRequest) Reset()         { *m = PublicIPAddressRequest{} }
func (m *PublicIPAddressRequest) String() string { return proto.CompactTextString(m) }
func (*PublicIPAddressRequest) ProtoMessage()    {}
func (*PublicIPAddressRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_35bf7f9bc887fae5, []int{0}
}

func (m *PublicIPAddressRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicIPAddressRequest.Unmarshal(m, b)
}
func (m *PublicIPAddressRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicIPAddressRequest.Marshal(b, m, deterministic)
}
func (m *PublicIPAddressRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicIPAddressRequest.Merge(m, src)
}
func (m *PublicIPAddressRequest) XXX_Size() int {
	return xxx_messageInfo_PublicIPAddressRequest.Size(m)
}
func (m *PublicIPAddressRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicIPAddressRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PublicIPAddressRequest proto.InternalMessageInfo

func (m *PublicIPAddressRequest) GetPublicIPAddresses() []*PublicIPAddress {
	if m != nil {
		return m.PublicIPAddresses
	}
	return nil
}

func (m *PublicIPAddressRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type PublicIPAddressResponse struct {
	PublicIPAddresses    []*PublicIPAddress  `protobuf:"bytes,1,rep,name=PublicIPAddresses,proto3" json:"PublicIPAddresses,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *PublicIPAddressResponse) Reset()         { *m = PublicIPAddressResponse{} }
func (m *PublicIPAddressResponse) String() string { return proto.CompactTextString(m) }
func (*PublicIPAddressResponse) ProtoMessage()    {}
func (*PublicIPAddressResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_35bf7f9bc887fae5, []int{1}
}

func (m *PublicIPAddressResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicIPAddressResponse.Unmarshal(m, b)
}
func (m *PublicIPAddressResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicIPAddressResponse.Marshal(b, m, deterministic)
}
func (m *PublicIPAddressResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicIPAddressResponse.Merge(m, src)
}
func (m *PublicIPAddressResponse) XXX_Size() int {
	return xxx_messageInfo_PublicIPAddressResponse.Size(m)
}
func (m *PublicIPAddressResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicIPAddressResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PublicIPAddressResponse proto.InternalMessageInfo

func (m *PublicIPAddressResponse) GetPublicIPAddresses() []*PublicIPAddress {
	if m != nil {
		return m.PublicIPAddresses
	}
	return nil
}

func (m *PublicIPAddressResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *PublicIPAddressResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type PublicIPAddressPrecheckRequest struct {
	PublicIPAddresses    []*PublicIPAddress `protobuf:"bytes,1,rep,name=PublicIPAddresses,proto3" json:"PublicIPAddresses,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *PublicIPAddressPrecheckRequest) Reset()         { *m = PublicIPAddressPrecheckRequest{} }
func (m *PublicIPAddressPrecheckRequest) String() string { return proto.CompactTextString(m) }
func (*PublicIPAddressPrecheckRequest) ProtoMessage()    {}
func (*PublicIPAddressPrecheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_35bf7f9bc887fae5, []int{2}
}

func (m *PublicIPAddressPrecheckRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicIPAddressPrecheckRequest.Unmarshal(m, b)
}
func (m *PublicIPAddressPrecheckRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicIPAddressPrecheckRequest.Marshal(b, m, deterministic)
}
func (m *PublicIPAddressPrecheckRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicIPAddressPrecheckRequest.Merge(m, src)
}
func (m *PublicIPAddressPrecheckRequest) XXX_Size() int {
	return xxx_messageInfo_PublicIPAddressPrecheckRequest.Size(m)
}
func (m *PublicIPAddressPrecheckRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicIPAddressPrecheckRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PublicIPAddressPrecheckRequest proto.InternalMessageInfo

func (m *PublicIPAddressPrecheckRequest) GetPublicIPAddresses() []*PublicIPAddress {
	if m != nil {
		return m.PublicIPAddresses
	}
	return nil
}

type PublicIPAddressPrecheckResponse struct {
	// The precheck result: true if the precheck criteria is passed; otherwise, false
	Result *wrappers.BoolValue `protobuf:"bytes,1,opt,name=Result,proto3" json:"Result,omitempty"`
	// The error message if the precheck is not passed; otherwise, empty string
	Error                string   `protobuf:"bytes,2,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PublicIPAddressPrecheckResponse) Reset()         { *m = PublicIPAddressPrecheckResponse{} }
func (m *PublicIPAddressPrecheckResponse) String() string { return proto.CompactTextString(m) }
func (*PublicIPAddressPrecheckResponse) ProtoMessage()    {}
func (*PublicIPAddressPrecheckResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_35bf7f9bc887fae5, []int{3}
}

func (m *PublicIPAddressPrecheckResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicIPAddressPrecheckResponse.Unmarshal(m, b)
}
func (m *PublicIPAddressPrecheckResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicIPAddressPrecheckResponse.Marshal(b, m, deterministic)
}
func (m *PublicIPAddressPrecheckResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicIPAddressPrecheckResponse.Merge(m, src)
}
func (m *PublicIPAddressPrecheckResponse) XXX_Size() int {
	return xxx_messageInfo_PublicIPAddressPrecheckResponse.Size(m)
}
func (m *PublicIPAddressPrecheckResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicIPAddressPrecheckResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PublicIPAddressPrecheckResponse proto.InternalMessageInfo

func (m *PublicIPAddressPrecheckResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *PublicIPAddressPrecheckResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type PublicIPAddress struct {
	Name                 string                    `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string                    `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	IpAddress            string                    `protobuf:"bytes,3,opt,name=ipAddress,proto3" json:"ipAddress,omitempty"`
	Allocation           common.IPAllocationMethod `protobuf:"varint,4,opt,name=allocation,proto3,enum=moc.IPAllocationMethod" json:"allocation,omitempty"`
	IpVersion            common.IPVersion          `protobuf:"varint,5,opt,name=ipVersion,proto3,enum=moc.IPVersion" json:"ipVersion,omitempty"`
	IdleTimeoutInMinutes uint32                    `protobuf:"varint,6,opt,name=idleTimeoutInMinutes,proto3" json:"idleTimeoutInMinutes,omitempty"`
	GroupName            string                    `protobuf:"bytes,7,opt,name=groupName,proto3" json:"groupName,omitempty"`
	LocationName         string                    `protobuf:"bytes,8,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Status               *common.Status            `protobuf:"bytes,9,opt,name=status,proto3" json:"status,omitempty"`
	Tags                 *common.Tags              `protobuf:"bytes,10,opt,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *PublicIPAddress) Reset()         { *m = PublicIPAddress{} }
func (m *PublicIPAddress) String() string { return proto.CompactTextString(m) }
func (*PublicIPAddress) ProtoMessage()    {}
func (*PublicIPAddress) Descriptor() ([]byte, []int) {
	return fileDescriptor_35bf7f9bc887fae5, []int{4}
}

func (m *PublicIPAddress) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicIPAddress.Unmarshal(m, b)
}
func (m *PublicIPAddress) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicIPAddress.Marshal(b, m, deterministic)
}
func (m *PublicIPAddress) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicIPAddress.Merge(m, src)
}
func (m *PublicIPAddress) XXX_Size() int {
	return xxx_messageInfo_PublicIPAddress.Size(m)
}
func (m *PublicIPAddress) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicIPAddress.DiscardUnknown(m)
}

var xxx_messageInfo_PublicIPAddress proto.InternalMessageInfo

func (m *PublicIPAddress) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *PublicIPAddress) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *PublicIPAddress) GetIpAddress() string {
	if m != nil {
		return m.IpAddress
	}
	return ""
}

func (m *PublicIPAddress) GetAllocation() common.IPAllocationMethod {
	if m != nil {
		return m.Allocation
	}
	return common.IPAllocationMethod_Invalid
}

func (m *PublicIPAddress) GetIpVersion() common.IPVersion {
	if m != nil {
		return m.IpVersion
	}
	return common.IPVersion_IPv4
}

func (m *PublicIPAddress) GetIdleTimeoutInMinutes() uint32 {
	if m != nil {
		return m.IdleTimeoutInMinutes
	}
	return 0
}

func (m *PublicIPAddress) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *PublicIPAddress) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *PublicIPAddress) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *PublicIPAddress) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func init() {
	proto.RegisterType((*PublicIPAddressRequest)(nil), "moc.cloudagent.network.PublicIPAddressRequest")
	proto.RegisterType((*PublicIPAddressResponse)(nil), "moc.cloudagent.network.PublicIPAddressResponse")
	proto.RegisterType((*PublicIPAddressPrecheckRequest)(nil), "moc.cloudagent.network.PublicIPAddressPrecheckRequest")
	proto.RegisterType((*PublicIPAddressPrecheckResponse)(nil), "moc.cloudagent.network.PublicIPAddressPrecheckResponse")
	proto.RegisterType((*PublicIPAddress)(nil), "moc.cloudagent.network.PublicIPAddress")
}

func init() {
	proto.RegisterFile("moc_cloudagent_publicipaddress.proto", fileDescriptor_35bf7f9bc887fae5)
}

var fileDescriptor_35bf7f9bc887fae5 = []byte{
	// 567 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x53, 0xc1, 0x6e, 0xd3, 0x40,
	0x10, 0xc5, 0x6e, 0x1a, 0xea, 0x29, 0x2d, 0x62, 0x55, 0x35, 0x56, 0x04, 0x21, 0x32, 0x48, 0xe4,
	0x80, 0x6c, 0x61, 0x10, 0x3d, 0x27, 0x12, 0x87, 0x1c, 0x0a, 0xd1, 0x12, 0x7a, 0xe0, 0x52, 0x39,
	0xf6, 0xd6, 0xb1, 0x62, 0x7b, 0xcc, 0xee, 0x9a, 0x88, 0x03, 0x17, 0x4e, 0xfc, 0x08, 0x9f, 0xc0,
	0x85, 0x4f, 0xe3, 0x84, 0xb2, 0xde, 0xd4, 0xa9, 0x5b, 0xa4, 0xf4, 0xd0, 0x93, 0xed, 0x79, 0x6f,
	0xde, 0xbe, 0x99, 0x7d, 0x86, 0xe7, 0x19, 0x86, 0xe7, 0x61, 0x8a, 0x65, 0x14, 0xc4, 0x2c, 0x97,
	0xe7, 0x45, 0x39, 0x4b, 0x93, 0x30, 0x29, 0x82, 0x28, 0xe2, 0x4c, 0x08, 0xb7, 0xe0, 0x28, 0x91,
	0x1c, 0x67, 0x18, 0xba, 0x35, 0xcb, 0xcd, 0x99, 0x5c, 0x22, 0x5f, 0x74, 0x7b, 0x31, 0x62, 0x9c,
	0x32, 0x4f, 0xb1, 0x66, 0xe5, 0x85, 0xb7, 0xe4, 0x41, 0x51, 0x30, 0xae, 0xfb, 0xba, 0x1d, 0xa5,
	0x8e, 0x59, 0x86, 0xb9, 0x7e, 0x68, 0xa0, 0xb7, 0x01, 0x68, 0xb1, 0x4d, 0xdc, 0xf9, 0x65, 0xc0,
	0xf1, 0x44, 0x59, 0x19, 0x4f, 0x86, 0x95, 0x15, 0xca, 0xbe, 0x94, 0x4c, 0x48, 0xf2, 0x09, 0x1e,
	0x35, 0x10, 0x26, 0x6c, 0xa3, 0xbf, 0x33, 0xd8, 0xf7, 0x5f, 0xb8, 0x37, 0xfb, 0x74, 0x9b, 0x52,
	0xd7, 0x15, 0xc8, 0x1b, 0x38, 0xf8, 0x50, 0x30, 0x1e, 0xc8, 0x04, 0xf3, 0xe9, 0xb7, 0x82, 0xd9,
	0x66, 0xdf, 0x18, 0x1c, 0xfa, 0x87, 0x4a, 0xf2, 0x12, 0xa1, 0x57, 0x49, 0xce, 0x1f, 0x03, 0x3a,
	0xd7, 0x7c, 0x8a, 0x02, 0x73, 0xc1, 0xee, 0xca, 0xa8, 0x0f, 0x6d, 0xca, 0x44, 0x99, 0x4a, 0xe5,
	0x70, 0xdf, 0xef, 0xba, 0xd5, 0x25, 0xb8, 0xeb, 0x4b, 0x70, 0x47, 0x88, 0xe9, 0x59, 0x90, 0x96,
	0x8c, 0x6a, 0x26, 0x39, 0x82, 0xdd, 0x77, 0x9c, 0x23, 0xb7, 0x77, 0xfa, 0xc6, 0xc0, 0xa2, 0xd5,
	0x87, 0xb3, 0x84, 0x5e, 0x43, 0x7e, 0xc2, 0x59, 0x38, 0x67, 0xe1, 0xe2, 0x6e, 0x77, 0xed, 0x2c,
	0xe0, 0xe9, 0x7f, 0x0f, 0xd6, 0xcb, 0xab, 0xa7, 0x34, 0x6e, 0x3f, 0xa5, 0xb9, 0x39, 0xe5, 0x5f,
	0x13, 0x1e, 0x36, 0x4e, 0x23, 0x04, 0x5a, 0x79, 0x90, 0x31, 0xa5, 0x6d, 0x51, 0xf5, 0x4e, 0x0e,
	0xc1, 0x4c, 0x22, 0xdd, 0x6a, 0x26, 0x11, 0x71, 0xc0, 0x4a, 0x0a, 0xdd, 0x50, 0xed, 0x6d, 0xd4,
	0xfa, 0xf9, 0xdb, 0x36, 0x68, 0x5d, 0x26, 0x27, 0x00, 0x41, 0x9a, 0x62, 0xa8, 0x02, 0x61, 0xb7,
	0x54, 0x62, 0x3a, 0x6a, 0x31, 0xe3, 0xc9, 0xf0, 0x12, 0x38, 0x65, 0x72, 0x8e, 0x11, 0xdd, 0xa0,
	0x92, 0x97, 0x2b, 0xf1, 0x33, 0xc6, 0xc5, 0xaa, 0x6f, 0x77, 0x23, 0x69, 0xe3, 0x89, 0xae, 0xd2,
	0x9a, 0x40, 0x7c, 0x38, 0x4a, 0xa2, 0x94, 0x4d, 0x93, 0x8c, 0x61, 0x29, 0xc7, 0xf9, 0x69, 0x92,
	0x97, 0x92, 0x09, 0xbb, 0xdd, 0x37, 0x06, 0x07, 0xf4, 0x46, 0x8c, 0x3c, 0x06, 0x2b, 0xe6, 0x58,
	0x16, 0xef, 0x57, 0x73, 0xde, 0x57, 0x53, 0xd5, 0x05, 0xe2, 0xc0, 0x83, 0xb5, 0x17, 0x45, 0xd8,
	0x53, 0x84, 0x2b, 0x35, 0xf2, 0x0c, 0xda, 0x42, 0x06, 0xb2, 0x14, 0xb6, 0xa5, 0xae, 0x60, 0x5f,
	0x19, 0xfc, 0xa8, 0x4a, 0x54, 0x43, 0xe4, 0x09, 0xb4, 0x64, 0x10, 0x0b, 0x1b, 0x14, 0xc5, 0x52,
	0x94, 0x69, 0x10, 0x0b, 0xaa, 0xca, 0xfe, 0x0f, 0x13, 0x8e, 0x1a, 0xcb, 0x1f, 0xae, 0xd2, 0x42,
	0x16, 0xd0, 0x1e, 0xe7, 0x5f, 0x71, 0xc1, 0x88, 0xbb, 0x6d, 0x90, 0xaa, 0x4c, 0x76, 0xbd, 0xad,
	0xf9, 0x55, 0x94, 0x9c, 0x7b, 0xe4, 0x3b, 0xec, 0xad, 0x03, 0x46, 0xde, 0x6e, 0xd9, 0xde, 0xf8,
	0x15, 0xba, 0x27, 0xb7, 0xee, 0x5b, 0x1f, 0x3f, 0x7a, 0xf5, 0xd9, 0x8b, 0x13, 0x39, 0x2f, 0x67,
	0x6e, 0x88, 0x99, 0x97, 0x25, 0x21, 0x47, 0x81, 0x17, 0xd2, 0xcb, 0x30, 0xf4, 0x78, 0x11, 0x7a,
	0xb5, 0xa8, 0xa7, 0x45, 0x67, 0x6d, 0x15, 0xf3, 0xd7, 0xff, 0x02, 0x00, 0x00, 0xff, 0xff, 0xa3,
	0xbe, 0x10, 0xbe, 0x9f, 0x05, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// PublicIPAddressAgentClient is the client API for PublicIPAddressAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type PublicIPAddressAgentClient interface {
	Invoke(ctx context.Context, in *PublicIPAddressRequest, opts ...grpc.CallOption) (*PublicIPAddressResponse, error)
	// Prechecks whether the system is able to create specified public IP address (but does not actually create them).
	Precheck(ctx context.Context, in *PublicIPAddressPrecheckRequest, opts ...grpc.CallOption) (*PublicIPAddressPrecheckResponse, error)
}

type publicIPAddressAgentClient struct {
	cc *grpc.ClientConn
}

func NewPublicIPAddressAgentClient(cc *grpc.ClientConn) PublicIPAddressAgentClient {
	return &publicIPAddressAgentClient{cc}
}

func (c *publicIPAddressAgentClient) Invoke(ctx context.Context, in *PublicIPAddressRequest, opts ...grpc.CallOption) (*PublicIPAddressResponse, error) {
	out := new(PublicIPAddressResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.PublicIPAddressAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *publicIPAddressAgentClient) Precheck(ctx context.Context, in *PublicIPAddressPrecheckRequest, opts ...grpc.CallOption) (*PublicIPAddressPrecheckResponse, error) {
	out := new(PublicIPAddressPrecheckResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.PublicIPAddressAgent/Precheck", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PublicIPAddressAgentServer is the server API for PublicIPAddressAgent service.
type PublicIPAddressAgentServer interface {
	Invoke(context.Context, *PublicIPAddressRequest) (*PublicIPAddressResponse, error)
	// Prechecks whether the system is able to create specified public IP address (but does not actually create them).
	Precheck(context.Context, *PublicIPAddressPrecheckRequest) (*PublicIPAddressPrecheckResponse, error)
}

// UnimplementedPublicIPAddressAgentServer can be embedded to have forward compatible implementations.
type UnimplementedPublicIPAddressAgentServer struct {
}

func (*UnimplementedPublicIPAddressAgentServer) Invoke(ctx context.Context, req *PublicIPAddressRequest) (*PublicIPAddressResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}
func (*UnimplementedPublicIPAddressAgentServer) Precheck(ctx context.Context, req *PublicIPAddressPrecheckRequest) (*PublicIPAddressPrecheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Precheck not implemented")
}

func RegisterPublicIPAddressAgentServer(s *grpc.Server, srv PublicIPAddressAgentServer) {
	s.RegisterService(&_PublicIPAddressAgent_serviceDesc, srv)
}

func _PublicIPAddressAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PublicIPAddressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PublicIPAddressAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.PublicIPAddressAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PublicIPAddressAgentServer).Invoke(ctx, req.(*PublicIPAddressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PublicIPAddressAgent_Precheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PublicIPAddressPrecheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PublicIPAddressAgentServer).Precheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.PublicIPAddressAgent/Precheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PublicIPAddressAgentServer).Precheck(ctx, req.(*PublicIPAddressPrecheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _PublicIPAddressAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.network.PublicIPAddressAgent",
	HandlerType: (*PublicIPAddressAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _PublicIPAddressAgent_Invoke_Handler,
		},
		{
			MethodName: "Precheck",
			Handler:    _PublicIPAddressAgent_Precheck_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_publicipaddress.proto",
}
