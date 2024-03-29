// Code generated by protoc-gen-go. DO NOT EDIT.
// source: admin/debug/moc_common_debug.proto

package admin

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

type DebugOperation int32

const (
	DebugOperation_DEBUGSERVER DebugOperation = 0
	DebugOperation_STACKTRACE  DebugOperation = 1
)

var DebugOperation_name = map[int32]string{
	0: "DEBUGSERVER",
	1: "STACKTRACE",
}

var DebugOperation_value = map[string]int32{
	"DEBUGSERVER": 0,
	"STACKTRACE":  1,
}

func (x DebugOperation) String() string {
	return proto.EnumName(DebugOperation_name, int32(x))
}

func (DebugOperation) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_329de964e3bb5c81, []int{0}
}

type DebugRequest struct {
	// Operation Type
	OBSOLETE_OperationType DebugOperation `protobuf:"varint,1,opt,name=OBSOLETE_OperationType,json=OBSOLETEOperationType,proto3,enum=moc.common.admin.DebugOperation" json:"OBSOLETE_OperationType,omitempty"` // Deprecated: Do not use.
	// Artibraty data
	Data                 string                         `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
	OperationType        common.ProviderAccessOperation `protobuf:"varint,3,opt,name=OperationType,proto3,enum=moc.ProviderAccessOperation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                       `json:"-"`
	XXX_unrecognized     []byte                         `json:"-"`
	XXX_sizecache        int32                          `json:"-"`
}

func (m *DebugRequest) Reset()         { *m = DebugRequest{} }
func (m *DebugRequest) String() string { return proto.CompactTextString(m) }
func (*DebugRequest) ProtoMessage()    {}
func (*DebugRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_329de964e3bb5c81, []int{0}
}

func (m *DebugRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DebugRequest.Unmarshal(m, b)
}
func (m *DebugRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DebugRequest.Marshal(b, m, deterministic)
}
func (m *DebugRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DebugRequest.Merge(m, src)
}
func (m *DebugRequest) XXX_Size() int {
	return xxx_messageInfo_DebugRequest.Size(m)
}
func (m *DebugRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_DebugRequest.DiscardUnknown(m)
}

var xxx_messageInfo_DebugRequest proto.InternalMessageInfo

// Deprecated: Do not use.
func (m *DebugRequest) GetOBSOLETE_OperationType() DebugOperation {
	if m != nil {
		return m.OBSOLETE_OperationType
	}
	return DebugOperation_DEBUGSERVER
}

func (m *DebugRequest) GetData() string {
	if m != nil {
		return m.Data
	}
	return ""
}

func (m *DebugRequest) GetOperationType() common.ProviderAccessOperation {
	if m != nil {
		return m.OperationType
	}
	return common.ProviderAccessOperation_Unspecified
}

type DebugResponse struct {
	Result               string   `protobuf:"bytes,1,opt,name=Result,proto3" json:"Result,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DebugResponse) Reset()         { *m = DebugResponse{} }
func (m *DebugResponse) String() string { return proto.CompactTextString(m) }
func (*DebugResponse) ProtoMessage()    {}
func (*DebugResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_329de964e3bb5c81, []int{1}
}

func (m *DebugResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DebugResponse.Unmarshal(m, b)
}
func (m *DebugResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DebugResponse.Marshal(b, m, deterministic)
}
func (m *DebugResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DebugResponse.Merge(m, src)
}
func (m *DebugResponse) XXX_Size() int {
	return xxx_messageInfo_DebugResponse.Size(m)
}
func (m *DebugResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_DebugResponse.DiscardUnknown(m)
}

var xxx_messageInfo_DebugResponse proto.InternalMessageInfo

func (m *DebugResponse) GetResult() string {
	if m != nil {
		return m.Result
	}
	return ""
}

func init() {
	proto.RegisterEnum("moc.common.admin.DebugOperation", DebugOperation_name, DebugOperation_value)
	proto.RegisterType((*DebugRequest)(nil), "moc.common.admin.DebugRequest")
	proto.RegisterType((*DebugResponse)(nil), "moc.common.admin.DebugResponse")
}

func init() {
	proto.RegisterFile("admin/debug/moc_common_debug.proto", fileDescriptor_329de964e3bb5c81)
}

var fileDescriptor_329de964e3bb5c81 = []byte{
	// 323 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x91, 0xe1, 0x4a, 0xc3, 0x30,
	0x10, 0x80, 0xd7, 0x29, 0x83, 0x9d, 0x6e, 0x8e, 0x80, 0x73, 0x0c, 0xd1, 0xd1, 0x3f, 0x4e, 0x85,
	0x16, 0xe7, 0x13, 0xb4, 0x5b, 0x11, 0x99, 0x30, 0xc9, 0xaa, 0xa0, 0xfe, 0x18, 0x5d, 0x16, 0x67,
	0xd1, 0xe6, 0x6a, 0x92, 0x0e, 0x7c, 0x3e, 0x5f, 0x4c, 0x96, 0xd6, 0x61, 0x85, 0xfd, 0x6b, 0xef,
	0xbe, 0xef, 0xee, 0x72, 0x07, 0x76, 0xb4, 0x48, 0x62, 0xe1, 0x2e, 0xf8, 0x3c, 0x5b, 0xba, 0x09,
	0xb2, 0x19, 0xc3, 0x24, 0x41, 0x31, 0x33, 0x01, 0x27, 0x95, 0xa8, 0x91, 0xb4, 0x12, 0x64, 0x4e,
	0x1e, 0x77, 0x0c, 0xde, 0x3d, 0xfa, 0x43, 0x16, 0x09, 0x83, 0xda, 0xdf, 0x16, 0xec, 0x8f, 0xd6,
	0x2a, 0xe5, 0x9f, 0x19, 0x57, 0x9a, 0xbc, 0x40, 0x7b, 0xe2, 0x4f, 0x27, 0x77, 0x41, 0x18, 0xcc,
	0x26, 0x29, 0x97, 0x91, 0x8e, 0x51, 0x84, 0x5f, 0x29, 0xef, 0x58, 0x3d, 0xab, 0xdf, 0x1c, 0xf4,
	0x9c, 0xff, 0xc5, 0x1d, 0xe3, 0x6f, 0x58, 0xbf, 0xda, 0xb1, 0xe8, 0xe1, 0x6f, 0x8d, 0x52, 0x09,
	0x42, 0x60, 0x77, 0x14, 0xe9, 0xa8, 0x53, 0xed, 0x59, 0xfd, 0x3a, 0x35, 0xdf, 0xc4, 0x87, 0x46,
	0xb9, 0xcf, 0x8e, 0xe9, 0x73, 0x6c, 0xfa, 0xdc, 0x4b, 0x5c, 0xc5, 0x0b, 0x2e, 0x3d, 0xc6, 0xb8,
	0x52, 0x1b, 0x8e, 0x96, 0x15, 0xfb, 0x0c, 0x1a, 0xc5, 0x23, 0x54, 0x8a, 0x42, 0x71, 0xd2, 0x86,
	0x1a, 0xe5, 0x2a, 0xfb, 0xd0, 0x66, 0xea, 0x3a, 0x2d, 0xfe, 0x2e, 0xae, 0xa0, 0x59, 0x9e, 0x96,
	0x1c, 0xc0, 0xde, 0x28, 0xf0, 0x1f, 0x6e, 0xa6, 0x01, 0x7d, 0x0c, 0x68, 0xab, 0x42, 0x9a, 0x00,
	0xd3, 0xd0, 0x1b, 0x8e, 0x43, 0xea, 0x0d, 0x83, 0x96, 0x35, 0x78, 0x02, 0x30, 0x8a, 0xb7, 0xe4,
	0x42, 0x93, 0x31, 0xd4, 0x6e, 0xc5, 0x0a, 0xdf, 0x39, 0x39, 0xd9, 0xb2, 0x88, 0x62, 0x91, 0xdd,
	0xd3, 0xad, 0xf9, 0x7c, 0x46, 0xbb, 0xe2, 0x5f, 0x3e, 0x9f, 0x2f, 0x63, 0xfd, 0x96, 0xcd, 0xd7,
	0x98, 0x9b, 0xc4, 0x4c, 0xa2, 0xc2, 0x57, 0xbd, 0x3e, 0xab, 0x2b, 0x53, 0xe6, 0xe6, 0xb2, 0x6b,
	0xe4, 0x79, 0xcd, 0x1c, 0xec, 0xfa, 0x27, 0x00, 0x00, 0xff, 0xff, 0xe1, 0x23, 0xdf, 0x97, 0x01,
	0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// DebugAgentClient is the client API for DebugAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type DebugAgentClient interface {
	Invoke(ctx context.Context, in *DebugRequest, opts ...grpc.CallOption) (*DebugResponse, error)
}

type debugAgentClient struct {
	cc *grpc.ClientConn
}

func NewDebugAgentClient(cc *grpc.ClientConn) DebugAgentClient {
	return &debugAgentClient{cc}
}

func (c *debugAgentClient) Invoke(ctx context.Context, in *DebugRequest, opts ...grpc.CallOption) (*DebugResponse, error) {
	out := new(DebugResponse)
	err := c.cc.Invoke(ctx, "/moc.common.admin.DebugAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DebugAgentServer is the server API for DebugAgent service.
type DebugAgentServer interface {
	Invoke(context.Context, *DebugRequest) (*DebugResponse, error)
}

// UnimplementedDebugAgentServer can be embedded to have forward compatible implementations.
type UnimplementedDebugAgentServer struct {
}

func (*UnimplementedDebugAgentServer) Invoke(ctx context.Context, req *DebugRequest) (*DebugResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}

func RegisterDebugAgentServer(s *grpc.Server, srv DebugAgentServer) {
	s.RegisterService(&_DebugAgent_serviceDesc, srv)
}

func _DebugAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DebugRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DebugAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.common.admin.DebugAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DebugAgentServer).Invoke(ctx, req.(*DebugRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _DebugAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.common.admin.DebugAgent",
	HandlerType: (*DebugAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _DebugAgent_Invoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "admin/debug/moc_common_debug.proto",
}
