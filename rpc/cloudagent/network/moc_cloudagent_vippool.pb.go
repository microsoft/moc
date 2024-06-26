// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_vippool.proto

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

type VipPoolRequest struct {
	VipPools             []*VipPool       `protobuf:"bytes,1,rep,name=VipPools,proto3" json:"VipPools,omitempty"`
	OperationType        common.Operation `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *VipPoolRequest) Reset()         { *m = VipPoolRequest{} }
func (m *VipPoolRequest) String() string { return proto.CompactTextString(m) }
func (*VipPoolRequest) ProtoMessage()    {}
func (*VipPoolRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_608cad7efbd0a4a0, []int{0}
}

func (m *VipPoolRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VipPoolRequest.Unmarshal(m, b)
}
func (m *VipPoolRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VipPoolRequest.Marshal(b, m, deterministic)
}
func (m *VipPoolRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VipPoolRequest.Merge(m, src)
}
func (m *VipPoolRequest) XXX_Size() int {
	return xxx_messageInfo_VipPoolRequest.Size(m)
}
func (m *VipPoolRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VipPoolRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VipPoolRequest proto.InternalMessageInfo

func (m *VipPoolRequest) GetVipPools() []*VipPool {
	if m != nil {
		return m.VipPools
	}
	return nil
}

func (m *VipPoolRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type VipPoolResponse struct {
	VipPools             []*VipPool          `protobuf:"bytes,1,rep,name=VipPools,proto3" json:"VipPools,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *VipPoolResponse) Reset()         { *m = VipPoolResponse{} }
func (m *VipPoolResponse) String() string { return proto.CompactTextString(m) }
func (*VipPoolResponse) ProtoMessage()    {}
func (*VipPoolResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_608cad7efbd0a4a0, []int{1}
}

func (m *VipPoolResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VipPoolResponse.Unmarshal(m, b)
}
func (m *VipPoolResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VipPoolResponse.Marshal(b, m, deterministic)
}
func (m *VipPoolResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VipPoolResponse.Merge(m, src)
}
func (m *VipPoolResponse) XXX_Size() int {
	return xxx_messageInfo_VipPoolResponse.Size(m)
}
func (m *VipPoolResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VipPoolResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VipPoolResponse proto.InternalMessageInfo

func (m *VipPoolResponse) GetVipPools() []*VipPool {
	if m != nil {
		return m.VipPools
	}
	return nil
}

func (m *VipPoolResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *VipPoolResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type VipPoolPrecheckRequest struct {
	VipPools             []*VipPool `protobuf:"bytes,1,rep,name=VipPools,proto3" json:"VipPools,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *VipPoolPrecheckRequest) Reset()         { *m = VipPoolPrecheckRequest{} }
func (m *VipPoolPrecheckRequest) String() string { return proto.CompactTextString(m) }
func (*VipPoolPrecheckRequest) ProtoMessage()    {}
func (*VipPoolPrecheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_608cad7efbd0a4a0, []int{2}
}

func (m *VipPoolPrecheckRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VipPoolPrecheckRequest.Unmarshal(m, b)
}
func (m *VipPoolPrecheckRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VipPoolPrecheckRequest.Marshal(b, m, deterministic)
}
func (m *VipPoolPrecheckRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VipPoolPrecheckRequest.Merge(m, src)
}
func (m *VipPoolPrecheckRequest) XXX_Size() int {
	return xxx_messageInfo_VipPoolPrecheckRequest.Size(m)
}
func (m *VipPoolPrecheckRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VipPoolPrecheckRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VipPoolPrecheckRequest proto.InternalMessageInfo

func (m *VipPoolPrecheckRequest) GetVipPools() []*VipPool {
	if m != nil {
		return m.VipPools
	}
	return nil
}

type VipPoolPrecheckResponse struct {
	// The precheck result: true if the precheck criteria is passed; otherwise, false
	Result *wrappers.BoolValue `protobuf:"bytes,1,opt,name=Result,proto3" json:"Result,omitempty"`
	// The error message if the precheck is not passed; otherwise, empty string
	Error                string   `protobuf:"bytes,2,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VipPoolPrecheckResponse) Reset()         { *m = VipPoolPrecheckResponse{} }
func (m *VipPoolPrecheckResponse) String() string { return proto.CompactTextString(m) }
func (*VipPoolPrecheckResponse) ProtoMessage()    {}
func (*VipPoolPrecheckResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_608cad7efbd0a4a0, []int{3}
}

func (m *VipPoolPrecheckResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VipPoolPrecheckResponse.Unmarshal(m, b)
}
func (m *VipPoolPrecheckResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VipPoolPrecheckResponse.Marshal(b, m, deterministic)
}
func (m *VipPoolPrecheckResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VipPoolPrecheckResponse.Merge(m, src)
}
func (m *VipPoolPrecheckResponse) XXX_Size() int {
	return xxx_messageInfo_VipPoolPrecheckResponse.Size(m)
}
func (m *VipPoolPrecheckResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VipPoolPrecheckResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VipPoolPrecheckResponse proto.InternalMessageInfo

func (m *VipPoolPrecheckResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *VipPoolPrecheckResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type VipPool struct {
	Name                 string         `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string         `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Cidr                 string         `protobuf:"bytes,3,opt,name=cidr,proto3" json:"cidr,omitempty"`
	Networkid            string         `protobuf:"bytes,4,opt,name=networkid,proto3" json:"networkid,omitempty"`
	Nodefqdn             string         `protobuf:"bytes,5,opt,name=nodefqdn,proto3" json:"nodefqdn,omitempty"`
	GroupName            string         `protobuf:"bytes,6,opt,name=groupName,proto3" json:"groupName,omitempty"`
	LocationName         string         `protobuf:"bytes,7,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Status               *common.Status `protobuf:"bytes,8,opt,name=status,proto3" json:"status,omitempty"`
	Startip              string         `protobuf:"bytes,9,opt,name=startip,proto3" json:"startip,omitempty"`
	Endip                string         `protobuf:"bytes,10,opt,name=endip,proto3" json:"endip,omitempty"`
	Tags                 *common.Tags   `protobuf:"bytes,11,opt,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *VipPool) Reset()         { *m = VipPool{} }
func (m *VipPool) String() string { return proto.CompactTextString(m) }
func (*VipPool) ProtoMessage()    {}
func (*VipPool) Descriptor() ([]byte, []int) {
	return fileDescriptor_608cad7efbd0a4a0, []int{4}
}

func (m *VipPool) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VipPool.Unmarshal(m, b)
}
func (m *VipPool) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VipPool.Marshal(b, m, deterministic)
}
func (m *VipPool) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VipPool.Merge(m, src)
}
func (m *VipPool) XXX_Size() int {
	return xxx_messageInfo_VipPool.Size(m)
}
func (m *VipPool) XXX_DiscardUnknown() {
	xxx_messageInfo_VipPool.DiscardUnknown(m)
}

var xxx_messageInfo_VipPool proto.InternalMessageInfo

func (m *VipPool) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *VipPool) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *VipPool) GetCidr() string {
	if m != nil {
		return m.Cidr
	}
	return ""
}

func (m *VipPool) GetNetworkid() string {
	if m != nil {
		return m.Networkid
	}
	return ""
}

func (m *VipPool) GetNodefqdn() string {
	if m != nil {
		return m.Nodefqdn
	}
	return ""
}

func (m *VipPool) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *VipPool) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *VipPool) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *VipPool) GetStartip() string {
	if m != nil {
		return m.Startip
	}
	return ""
}

func (m *VipPool) GetEndip() string {
	if m != nil {
		return m.Endip
	}
	return ""
}

func (m *VipPool) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func init() {
	proto.RegisterType((*VipPoolRequest)(nil), "moc.cloudagent.network.VipPoolRequest")
	proto.RegisterType((*VipPoolResponse)(nil), "moc.cloudagent.network.VipPoolResponse")
	proto.RegisterType((*VipPoolPrecheckRequest)(nil), "moc.cloudagent.network.VipPoolPrecheckRequest")
	proto.RegisterType((*VipPoolPrecheckResponse)(nil), "moc.cloudagent.network.VipPoolPrecheckResponse")
	proto.RegisterType((*VipPool)(nil), "moc.cloudagent.network.VipPool")
}

func init() { proto.RegisterFile("moc_cloudagent_vippool.proto", fileDescriptor_608cad7efbd0a4a0) }

var fileDescriptor_608cad7efbd0a4a0 = []byte{
	// 525 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x52, 0xcd, 0x6e, 0xd3, 0x4c,
	0x14, 0xfd, 0x9c, 0xe6, 0xf7, 0xa6, 0x5f, 0x90, 0x46, 0xa8, 0xb5, 0xac, 0x52, 0x22, 0x23, 0x41,
	0x56, 0xb6, 0x08, 0xec, 0x58, 0x11, 0x89, 0x05, 0x1b, 0xa8, 0x4c, 0xe9, 0x02, 0x16, 0x95, 0x33,
	0x9e, 0xb8, 0xa3, 0xd8, 0x73, 0xa7, 0x33, 0xe3, 0x56, 0xac, 0xd9, 0xf0, 0x08, 0xbc, 0x08, 0x4b,
	0x5e, 0x84, 0xa7, 0x41, 0x19, 0x8f, 0x9d, 0x16, 0x90, 0x02, 0x82, 0x95, 0x3d, 0xe7, 0x9e, 0x73,
	0xee, 0x9d, 0x33, 0x17, 0x8e, 0x4a, 0xa4, 0xe7, 0xb4, 0xc0, 0x2a, 0x4b, 0x73, 0x26, 0xcc, 0xf9,
	0x15, 0x97, 0x12, 0xb1, 0x88, 0xa4, 0x42, 0x83, 0xe4, 0xa0, 0x44, 0x1a, 0x6d, 0xab, 0x91, 0x60,
	0xe6, 0x1a, 0xd5, 0x3a, 0x38, 0xce, 0x11, 0xf3, 0x82, 0xc5, 0x96, 0xb5, 0xac, 0x56, 0xf1, 0xb5,
	0x4a, 0xa5, 0x64, 0x4a, 0xd7, 0xba, 0xe0, 0xd0, 0xba, 0x62, 0x59, 0xa2, 0x70, 0x9f, 0xba, 0x10,
	0x7e, 0xf4, 0x60, 0x72, 0xc6, 0xe5, 0x09, 0x62, 0x91, 0xb0, 0xcb, 0x8a, 0x69, 0x43, 0x9e, 0xc1,
	0xd0, 0x21, 0xda, 0xf7, 0xa6, 0x7b, 0xb3, 0xf1, 0xfc, 0x7e, 0xf4, 0xeb, 0xb6, 0x51, 0xa3, 0x6c,
	0x05, 0xe4, 0x29, 0xfc, 0xff, 0x5a, 0x32, 0x95, 0x1a, 0x8e, 0xe2, 0xf4, 0x83, 0x64, 0x7e, 0x67,
	0xea, 0xcd, 0x26, 0xf3, 0x89, 0x75, 0x68, 0x2b, 0xc9, 0x6d, 0x52, 0xf8, 0xd9, 0x83, 0x3b, 0xed,
	0x14, 0x5a, 0xa2, 0xd0, 0xec, 0xef, 0xc6, 0x98, 0x43, 0x3f, 0x61, 0xba, 0x2a, 0x8c, 0xed, 0x3f,
	0x9e, 0x07, 0x51, 0x1d, 0x50, 0xd4, 0x04, 0x14, 0x2d, 0x10, 0x8b, 0xb3, 0xb4, 0xa8, 0x58, 0xe2,
	0x98, 0xe4, 0x2e, 0xf4, 0x5e, 0x28, 0x85, 0xca, 0xdf, 0x9b, 0x7a, 0xb3, 0x51, 0x52, 0x1f, 0xc2,
	0xb7, 0x70, 0xe0, 0x5c, 0x4f, 0x14, 0xa3, 0x17, 0x8c, 0xae, 0xff, 0x45, 0x4e, 0x21, 0x85, 0xc3,
	0x9f, 0x6c, 0xdd, 0xc5, 0xb7, 0xb3, 0x7b, 0x7f, 0x3e, 0x7b, 0xe7, 0xe6, 0xec, 0x5f, 0x3b, 0x30,
	0x70, 0x5d, 0x08, 0x81, 0xae, 0x48, 0x4b, 0x66, 0x3d, 0x47, 0x89, 0xfd, 0x27, 0x13, 0xe8, 0xf0,
	0xcc, 0x49, 0x3a, 0x3c, 0xdb, 0x70, 0x28, 0xcf, 0x9a, 0x00, 0xec, 0x3f, 0x39, 0x82, 0x91, 0xbb,
	0x05, 0xcf, 0xfc, 0xae, 0x2d, 0x6c, 0x01, 0x12, 0xc0, 0x50, 0x60, 0xc6, 0x56, 0x97, 0x99, 0xf0,
	0x7b, 0xb6, 0xd8, 0x9e, 0x37, 0xca, 0x5c, 0x61, 0x25, 0x5f, 0x6d, 0xda, 0xf6, 0x6b, 0x65, 0x0b,
	0x90, 0x10, 0xf6, 0x0b, 0xa4, 0x76, 0x05, 0x2c, 0x61, 0x60, 0x09, 0xb7, 0x30, 0xf2, 0x00, 0xfa,
	0xda, 0xa4, 0xa6, 0xd2, 0xfe, 0xd0, 0x26, 0x31, 0xb6, 0xf9, 0xbe, 0xb1, 0x50, 0xe2, 0x4a, 0xe4,
	0x18, 0x06, 0xda, 0xa4, 0xca, 0x70, 0xe9, 0x8f, 0x36, 0x1e, 0x8b, 0xee, 0xa7, 0x2f, 0xbe, 0x97,
	0x34, 0x20, 0x09, 0xa0, 0xc7, 0x44, 0xc6, 0xa5, 0x0f, 0x37, 0xaa, 0x35, 0x44, 0xee, 0x41, 0xd7,
	0xa4, 0xb9, 0xf6, 0xc7, 0xd6, 0x7e, 0x64, 0xed, 0x4f, 0xd3, 0x5c, 0x27, 0x16, 0x9e, 0x7f, 0xf3,
	0x60, 0xdf, 0xe5, 0xf7, 0x7c, 0xf3, 0x9e, 0xe4, 0x3d, 0xf4, 0x5f, 0x8a, 0x2b, 0x5c, 0x33, 0xf2,
	0x70, 0xd7, 0x53, 0xd7, 0x4b, 0x12, 0x3c, 0xda, 0xc9, 0xab, 0x5f, 0x3d, 0xfc, 0x8f, 0x94, 0x30,
	0x6c, 0x76, 0x81, 0x44, 0x3b, 0x64, 0x3f, 0xec, 0x62, 0x10, 0xff, 0x36, 0xbf, 0x69, 0xb7, 0x78,
	0xfc, 0x2e, 0xce, 0xb9, 0xb9, 0xa8, 0x96, 0x11, 0xc5, 0x32, 0x2e, 0x39, 0x55, 0xa8, 0x71, 0x65,
	0xe2, 0x12, 0x69, 0xac, 0x24, 0x8d, 0xb7, 0x66, 0xb1, 0x33, 0x5b, 0xf6, 0xed, 0x06, 0x3e, 0xf9,
	0x1e, 0x00, 0x00, 0xff, 0xff, 0x43, 0x3c, 0xe5, 0x06, 0xa4, 0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// VipPoolAgentClient is the client API for VipPoolAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type VipPoolAgentClient interface {
	Invoke(ctx context.Context, in *VipPoolRequest, opts ...grpc.CallOption) (*VipPoolResponse, error)
	// Prechecks whether the system is able to create specified vip pools (but does not actually create them).
	Precheck(ctx context.Context, in *VipPoolPrecheckRequest, opts ...grpc.CallOption) (*VipPoolPrecheckResponse, error)
}

type vipPoolAgentClient struct {
	cc *grpc.ClientConn
}

func NewVipPoolAgentClient(cc *grpc.ClientConn) VipPoolAgentClient {
	return &vipPoolAgentClient{cc}
}

func (c *vipPoolAgentClient) Invoke(ctx context.Context, in *VipPoolRequest, opts ...grpc.CallOption) (*VipPoolResponse, error) {
	out := new(VipPoolResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.VipPoolAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *vipPoolAgentClient) Precheck(ctx context.Context, in *VipPoolPrecheckRequest, opts ...grpc.CallOption) (*VipPoolPrecheckResponse, error) {
	out := new(VipPoolPrecheckResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.VipPoolAgent/Precheck", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VipPoolAgentServer is the server API for VipPoolAgent service.
type VipPoolAgentServer interface {
	Invoke(context.Context, *VipPoolRequest) (*VipPoolResponse, error)
	// Prechecks whether the system is able to create specified vip pools (but does not actually create them).
	Precheck(context.Context, *VipPoolPrecheckRequest) (*VipPoolPrecheckResponse, error)
}

// UnimplementedVipPoolAgentServer can be embedded to have forward compatible implementations.
type UnimplementedVipPoolAgentServer struct {
}

func (*UnimplementedVipPoolAgentServer) Invoke(ctx context.Context, req *VipPoolRequest) (*VipPoolResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}
func (*UnimplementedVipPoolAgentServer) Precheck(ctx context.Context, req *VipPoolPrecheckRequest) (*VipPoolPrecheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Precheck not implemented")
}

func RegisterVipPoolAgentServer(s *grpc.Server, srv VipPoolAgentServer) {
	s.RegisterService(&_VipPoolAgent_serviceDesc, srv)
}

func _VipPoolAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VipPoolRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VipPoolAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.VipPoolAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VipPoolAgentServer).Invoke(ctx, req.(*VipPoolRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _VipPoolAgent_Precheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VipPoolPrecheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VipPoolAgentServer).Precheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.VipPoolAgent/Precheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VipPoolAgentServer).Precheck(ctx, req.(*VipPoolPrecheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _VipPoolAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.network.VipPoolAgent",
	HandlerType: (*VipPoolAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _VipPoolAgent_Invoke_Handler,
		},
		{
			MethodName: "Precheck",
			Handler:    _VipPoolAgent_Precheck_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_vippool.proto",
}
