// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_macpool.proto

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

type MacPoolRequest struct {
	MacPools             []*MacPool       `protobuf:"bytes,1,rep,name=MacPools,proto3" json:"MacPools,omitempty"`
	OperationType        common.Operation `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *MacPoolRequest) Reset()         { *m = MacPoolRequest{} }
func (m *MacPoolRequest) String() string { return proto.CompactTextString(m) }
func (*MacPoolRequest) ProtoMessage()    {}
func (*MacPoolRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_53e61bc69a03dcef, []int{0}
}

func (m *MacPoolRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MacPoolRequest.Unmarshal(m, b)
}
func (m *MacPoolRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MacPoolRequest.Marshal(b, m, deterministic)
}
func (m *MacPoolRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MacPoolRequest.Merge(m, src)
}
func (m *MacPoolRequest) XXX_Size() int {
	return xxx_messageInfo_MacPoolRequest.Size(m)
}
func (m *MacPoolRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MacPoolRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MacPoolRequest proto.InternalMessageInfo

func (m *MacPoolRequest) GetMacPools() []*MacPool {
	if m != nil {
		return m.MacPools
	}
	return nil
}

func (m *MacPoolRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type MacPoolResponse struct {
	MacPools             []*MacPool          `protobuf:"bytes,1,rep,name=MacPools,proto3" json:"MacPools,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *MacPoolResponse) Reset()         { *m = MacPoolResponse{} }
func (m *MacPoolResponse) String() string { return proto.CompactTextString(m) }
func (*MacPoolResponse) ProtoMessage()    {}
func (*MacPoolResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_53e61bc69a03dcef, []int{1}
}

func (m *MacPoolResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MacPoolResponse.Unmarshal(m, b)
}
func (m *MacPoolResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MacPoolResponse.Marshal(b, m, deterministic)
}
func (m *MacPoolResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MacPoolResponse.Merge(m, src)
}
func (m *MacPoolResponse) XXX_Size() int {
	return xxx_messageInfo_MacPoolResponse.Size(m)
}
func (m *MacPoolResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MacPoolResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MacPoolResponse proto.InternalMessageInfo

func (m *MacPoolResponse) GetMacPools() []*MacPool {
	if m != nil {
		return m.MacPools
	}
	return nil
}

func (m *MacPoolResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *MacPoolResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type MacPoolPrecheckRequest struct {
	MacPools             []*MacPool `protobuf:"bytes,1,rep,name=MacPools,proto3" json:"MacPools,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *MacPoolPrecheckRequest) Reset()         { *m = MacPoolPrecheckRequest{} }
func (m *MacPoolPrecheckRequest) String() string { return proto.CompactTextString(m) }
func (*MacPoolPrecheckRequest) ProtoMessage()    {}
func (*MacPoolPrecheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_53e61bc69a03dcef, []int{2}
}

func (m *MacPoolPrecheckRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MacPoolPrecheckRequest.Unmarshal(m, b)
}
func (m *MacPoolPrecheckRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MacPoolPrecheckRequest.Marshal(b, m, deterministic)
}
func (m *MacPoolPrecheckRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MacPoolPrecheckRequest.Merge(m, src)
}
func (m *MacPoolPrecheckRequest) XXX_Size() int {
	return xxx_messageInfo_MacPoolPrecheckRequest.Size(m)
}
func (m *MacPoolPrecheckRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MacPoolPrecheckRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MacPoolPrecheckRequest proto.InternalMessageInfo

func (m *MacPoolPrecheckRequest) GetMacPools() []*MacPool {
	if m != nil {
		return m.MacPools
	}
	return nil
}

type MacPoolPrecheckResponse struct {
	// The precheck result: true if the precheck criteria is passed; otherwise, false
	Result *wrappers.BoolValue `protobuf:"bytes,1,opt,name=Result,proto3" json:"Result,omitempty"`
	// The error message if the precheck is not passed; otherwise, empty string
	Error                string   `protobuf:"bytes,2,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MacPoolPrecheckResponse) Reset()         { *m = MacPoolPrecheckResponse{} }
func (m *MacPoolPrecheckResponse) String() string { return proto.CompactTextString(m) }
func (*MacPoolPrecheckResponse) ProtoMessage()    {}
func (*MacPoolPrecheckResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_53e61bc69a03dcef, []int{3}
}

func (m *MacPoolPrecheckResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MacPoolPrecheckResponse.Unmarshal(m, b)
}
func (m *MacPoolPrecheckResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MacPoolPrecheckResponse.Marshal(b, m, deterministic)
}
func (m *MacPoolPrecheckResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MacPoolPrecheckResponse.Merge(m, src)
}
func (m *MacPoolPrecheckResponse) XXX_Size() int {
	return xxx_messageInfo_MacPoolPrecheckResponse.Size(m)
}
func (m *MacPoolPrecheckResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MacPoolPrecheckResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MacPoolPrecheckResponse proto.InternalMessageInfo

func (m *MacPoolPrecheckResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *MacPoolPrecheckResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type MacRange struct {
	StartMacAddress      string   `protobuf:"bytes,1,opt,name=startMacAddress,proto3" json:"startMacAddress,omitempty"`
	EndMacAddress        string   `protobuf:"bytes,2,opt,name=endMacAddress,proto3" json:"endMacAddress,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MacRange) Reset()         { *m = MacRange{} }
func (m *MacRange) String() string { return proto.CompactTextString(m) }
func (*MacRange) ProtoMessage()    {}
func (*MacRange) Descriptor() ([]byte, []int) {
	return fileDescriptor_53e61bc69a03dcef, []int{4}
}

func (m *MacRange) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MacRange.Unmarshal(m, b)
}
func (m *MacRange) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MacRange.Marshal(b, m, deterministic)
}
func (m *MacRange) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MacRange.Merge(m, src)
}
func (m *MacRange) XXX_Size() int {
	return xxx_messageInfo_MacRange.Size(m)
}
func (m *MacRange) XXX_DiscardUnknown() {
	xxx_messageInfo_MacRange.DiscardUnknown(m)
}

var xxx_messageInfo_MacRange proto.InternalMessageInfo

func (m *MacRange) GetStartMacAddress() string {
	if m != nil {
		return m.StartMacAddress
	}
	return ""
}

func (m *MacRange) GetEndMacAddress() string {
	if m != nil {
		return m.EndMacAddress
	}
	return ""
}

type MacPool struct {
	Name                 string         `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string         `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Range                *MacRange      `protobuf:"bytes,3,opt,name=range,proto3" json:"range,omitempty"`
	LocationName         string         `protobuf:"bytes,4,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Status               *common.Status `protobuf:"bytes,6,opt,name=status,proto3" json:"status,omitempty"`
	Tags                 *common.Tags   `protobuf:"bytes,7,opt,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *MacPool) Reset()         { *m = MacPool{} }
func (m *MacPool) String() string { return proto.CompactTextString(m) }
func (*MacPool) ProtoMessage()    {}
func (*MacPool) Descriptor() ([]byte, []int) {
	return fileDescriptor_53e61bc69a03dcef, []int{5}
}

func (m *MacPool) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MacPool.Unmarshal(m, b)
}
func (m *MacPool) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MacPool.Marshal(b, m, deterministic)
}
func (m *MacPool) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MacPool.Merge(m, src)
}
func (m *MacPool) XXX_Size() int {
	return xxx_messageInfo_MacPool.Size(m)
}
func (m *MacPool) XXX_DiscardUnknown() {
	xxx_messageInfo_MacPool.DiscardUnknown(m)
}

var xxx_messageInfo_MacPool proto.InternalMessageInfo

func (m *MacPool) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *MacPool) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *MacPool) GetRange() *MacRange {
	if m != nil {
		return m.Range
	}
	return nil
}

func (m *MacPool) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *MacPool) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *MacPool) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func init() {
	proto.RegisterType((*MacPoolRequest)(nil), "moc.cloudagent.network.MacPoolRequest")
	proto.RegisterType((*MacPoolResponse)(nil), "moc.cloudagent.network.MacPoolResponse")
	proto.RegisterType((*MacPoolPrecheckRequest)(nil), "moc.cloudagent.network.MacPoolPrecheckRequest")
	proto.RegisterType((*MacPoolPrecheckResponse)(nil), "moc.cloudagent.network.MacPoolPrecheckResponse")
	proto.RegisterType((*MacRange)(nil), "moc.cloudagent.network.MacRange")
	proto.RegisterType((*MacPool)(nil), "moc.cloudagent.network.MacPool")
}

func init() { proto.RegisterFile("moc_cloudagent_macpool.proto", fileDescriptor_53e61bc69a03dcef) }

var fileDescriptor_53e61bc69a03dcef = []byte{
	// 502 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x92, 0xcf, 0x6e, 0xd3, 0x40,
	0x10, 0xc6, 0x71, 0x9a, 0xa6, 0xcd, 0xa4, 0x4d, 0xa5, 0x15, 0x6a, 0x2d, 0x8b, 0x3f, 0x91, 0x41,
	0x90, 0xd3, 0x5a, 0x18, 0xc4, 0x85, 0x53, 0x2b, 0x71, 0xe0, 0x50, 0xa8, 0x96, 0xc2, 0xa1, 0x1c,
	0xaa, 0xcd, 0x7a, 0xeb, 0x5a, 0xf1, 0x7a, 0xcc, 0xee, 0x9a, 0x8a, 0x33, 0x2f, 0xc1, 0x4b, 0xf1,
	0x02, 0x3c, 0x0d, 0xca, 0x7a, 0x93, 0x34, 0x05, 0x11, 0x10, 0x9c, 0x12, 0xcf, 0x7c, 0xf3, 0x9b,
	0x6f, 0x67, 0x06, 0xee, 0x28, 0x14, 0xe7, 0xa2, 0xc4, 0x26, 0xe3, 0xb9, 0xac, 0xec, 0xb9, 0xe2,
	0xa2, 0x46, 0x2c, 0x69, 0xad, 0xd1, 0x22, 0xd9, 0x57, 0x28, 0xe8, 0x32, 0x4b, 0x2b, 0x69, 0xaf,
	0x50, 0x4f, 0xa3, 0x7b, 0x39, 0x62, 0x5e, 0xca, 0xc4, 0xa9, 0x26, 0xcd, 0x45, 0x72, 0xa5, 0x79,
	0x5d, 0x4b, 0x6d, 0xda, 0xba, 0xe8, 0xc0, 0x51, 0x51, 0x29, 0xac, 0xfc, 0x4f, 0x9b, 0x88, 0xbf,
	0x04, 0x30, 0x3c, 0xe6, 0xe2, 0x04, 0xb1, 0x64, 0xf2, 0x63, 0x23, 0x8d, 0x25, 0x2f, 0x60, 0xdb,
	0x47, 0x4c, 0x18, 0x8c, 0x36, 0xc6, 0x83, 0xf4, 0x3e, 0xfd, 0x75, 0x5b, 0x3a, 0xaf, 0x5c, 0x14,
	0x90, 0x67, 0xb0, 0xfb, 0xa6, 0x96, 0x9a, 0xdb, 0x02, 0xab, 0xd3, 0xcf, 0xb5, 0x0c, 0x3b, 0xa3,
	0x60, 0x3c, 0x4c, 0x87, 0x8e, 0xb0, 0xc8, 0xb0, 0x55, 0x51, 0xfc, 0x35, 0x80, 0xbd, 0x85, 0x0b,
	0x53, 0x63, 0x65, 0xe4, 0xbf, 0xd9, 0x48, 0xa1, 0xc7, 0xa4, 0x69, 0x4a, 0xeb, 0xfa, 0x0f, 0xd2,
	0x88, 0xb6, 0x03, 0xa2, 0xf3, 0x01, 0xd1, 0x23, 0xc4, 0xf2, 0x3d, 0x2f, 0x1b, 0xc9, 0xbc, 0x92,
	0xdc, 0x86, 0xcd, 0x97, 0x5a, 0xa3, 0x0e, 0x37, 0x46, 0xc1, 0xb8, 0xcf, 0xda, 0x8f, 0xf8, 0x1d,
	0xec, 0x7b, 0xea, 0x89, 0x96, 0xe2, 0x52, 0x8a, 0xe9, 0xff, 0x98, 0x53, 0x2c, 0xe0, 0xe0, 0x27,
	0xac, 0x7f, 0xf8, 0xd2, 0x7b, 0xf0, 0xf7, 0xde, 0x3b, 0xd7, 0xbd, 0x9f, 0x39, 0x87, 0x8c, 0x57,
	0xb9, 0x24, 0x63, 0xd8, 0x33, 0x96, 0x6b, 0x7b, 0xcc, 0xc5, 0x61, 0x96, 0x69, 0x69, 0x8c, 0xc3,
	0xf7, 0xd9, 0xcd, 0x30, 0x79, 0x08, 0xbb, 0xb2, 0xca, 0xae, 0xe9, 0x5a, 0xe6, 0x6a, 0x30, 0xfe,
	0x16, 0xc0, 0x96, 0x7f, 0x01, 0x21, 0xd0, 0xad, 0xb8, 0x92, 0x1e, 0xe8, 0xfe, 0x93, 0x21, 0x74,
	0x8a, 0xcc, 0x97, 0x76, 0x8a, 0x8c, 0x3c, 0x87, 0x4d, 0x3d, 0x33, 0xe2, 0xa6, 0x3b, 0x48, 0x47,
	0xbf, 0x19, 0x95, 0x33, 0xcc, 0x5a, 0x39, 0x89, 0x61, 0xa7, 0x44, 0xe1, 0x4e, 0xe5, 0xf5, 0xac,
	0x47, 0xd7, 0x11, 0x57, 0x62, 0xe4, 0x01, 0xf4, 0x8c, 0xe5, 0xb6, 0x31, 0x61, 0xcf, 0xc1, 0x07,
	0x0e, 0xfe, 0xd6, 0x85, 0x98, 0x4f, 0x91, 0xbb, 0xd0, 0xb5, 0x3c, 0x37, 0xe1, 0x96, 0x93, 0xf4,
	0x9d, 0xe4, 0x94, 0xe7, 0x86, 0xb9, 0x70, 0xfa, 0x3d, 0x80, 0x1d, 0xff, 0x9e, 0xc3, 0x99, 0x21,
	0xf2, 0x01, 0x7a, 0xaf, 0xaa, 0x4f, 0x38, 0x95, 0xe4, 0xd1, 0xba, 0xb5, 0xb6, 0x07, 0x11, 0x3d,
	0x5e, 0xab, 0x6b, 0x37, 0x1c, 0xdf, 0x22, 0x0a, 0xb6, 0xe7, 0x7b, 0x27, 0x74, 0x4d, 0xd9, 0x8d,
	0xbb, 0x8b, 0x92, 0x3f, 0xd6, 0xcf, 0xdb, 0x1d, 0x3d, 0x39, 0x4b, 0xf2, 0xc2, 0x5e, 0x36, 0x13,
	0x2a, 0x50, 0x25, 0xaa, 0x10, 0x1a, 0x0d, 0x5e, 0xd8, 0x44, 0xa1, 0x48, 0x74, 0x2d, 0x92, 0x25,
	0x2c, 0xf1, 0xb0, 0x49, 0xcf, 0x5d, 0xdb, 0xd3, 0x1f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x18, 0x61,
	0xfe, 0x93, 0x90, 0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// MacPoolAgentClient is the client API for MacPoolAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MacPoolAgentClient interface {
	Invoke(ctx context.Context, in *MacPoolRequest, opts ...grpc.CallOption) (*MacPoolResponse, error)
	// Prechecks whether the system is able to create specified MAC pools (but does not actually create them).
	Precheck(ctx context.Context, in *MacPoolPrecheckRequest, opts ...grpc.CallOption) (*MacPoolPrecheckResponse, error)
}

type macPoolAgentClient struct {
	cc *grpc.ClientConn
}

func NewMacPoolAgentClient(cc *grpc.ClientConn) MacPoolAgentClient {
	return &macPoolAgentClient{cc}
}

func (c *macPoolAgentClient) Invoke(ctx context.Context, in *MacPoolRequest, opts ...grpc.CallOption) (*MacPoolResponse, error) {
	out := new(MacPoolResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.MacPoolAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *macPoolAgentClient) Precheck(ctx context.Context, in *MacPoolPrecheckRequest, opts ...grpc.CallOption) (*MacPoolPrecheckResponse, error) {
	out := new(MacPoolPrecheckResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.MacPoolAgent/Precheck", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MacPoolAgentServer is the server API for MacPoolAgent service.
type MacPoolAgentServer interface {
	Invoke(context.Context, *MacPoolRequest) (*MacPoolResponse, error)
	// Prechecks whether the system is able to create specified MAC pools (but does not actually create them).
	Precheck(context.Context, *MacPoolPrecheckRequest) (*MacPoolPrecheckResponse, error)
}

// UnimplementedMacPoolAgentServer can be embedded to have forward compatible implementations.
type UnimplementedMacPoolAgentServer struct {
}

func (*UnimplementedMacPoolAgentServer) Invoke(ctx context.Context, req *MacPoolRequest) (*MacPoolResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}
func (*UnimplementedMacPoolAgentServer) Precheck(ctx context.Context, req *MacPoolPrecheckRequest) (*MacPoolPrecheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Precheck not implemented")
}

func RegisterMacPoolAgentServer(s *grpc.Server, srv MacPoolAgentServer) {
	s.RegisterService(&_MacPoolAgent_serviceDesc, srv)
}

func _MacPoolAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MacPoolRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MacPoolAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.MacPoolAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MacPoolAgentServer).Invoke(ctx, req.(*MacPoolRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MacPoolAgent_Precheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MacPoolPrecheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MacPoolAgentServer).Precheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.MacPoolAgent/Precheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MacPoolAgentServer).Precheck(ctx, req.(*MacPoolPrecheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _MacPoolAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.network.MacPoolAgent",
	HandlerType: (*MacPoolAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _MacPoolAgent_Invoke_Handler,
		},
		{
			MethodName: "Precheck",
			Handler:    _MacPoolAgent_Precheck_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_macpool.proto",
}
