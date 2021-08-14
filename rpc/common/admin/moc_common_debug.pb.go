// Code generated by protoc-gen-go. DO NOT EDIT.
// source: admin/debug/moc_common_debug.proto

package admin

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

type Operation int32

const (
	Operation_DEBUGSERVER Operation = 0
	Operation_STACKTRACE  Operation = 1
)

var Operation_name = map[int32]string{
	0: "DEBUGSERVER",
	1: "STACKTRACE",
}

var Operation_value = map[string]int32{
	"DEBUGSERVER": 0,
	"STACKTRACE":  1,
}

func (x Operation) String() string {
	return proto.EnumName(Operation_name, int32(x))
}

func (Operation) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_329de964e3bb5c81, []int{0}
}

type DebugRequest struct {
	// Operation Type
	OperationType Operation `protobuf:"varint,1,opt,name=OperationType,proto3,enum=moc.common.admin.Operation" json:"OperationType,omitempty"`
	// Artibraty data
	Data                 string   `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
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

func (m *DebugRequest) GetOperationType() Operation {
	if m != nil {
		return m.OperationType
	}
	return Operation_DEBUGSERVER
}

func (m *DebugRequest) GetData() string {
	if m != nil {
		return m.Data
	}
	return ""
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
	proto.RegisterEnum("moc.common.admin.Operation", Operation_name, Operation_value)
	proto.RegisterType((*DebugRequest)(nil), "moc.common.admin.DebugRequest")
	proto.RegisterType((*DebugResponse)(nil), "moc.common.admin.DebugResponse")
}

func init() {
	proto.RegisterFile("admin/debug/moc_common_debug.proto", fileDescriptor_329de964e3bb5c81)
}

var fileDescriptor_329de964e3bb5c81 = []byte{
	// 272 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x90, 0xdf, 0x4b, 0xc3, 0x30,
	0x10, 0xc7, 0x57, 0x91, 0x41, 0x4f, 0x37, 0x4b, 0x1e, 0x64, 0x28, 0xe8, 0xe8, 0x8b, 0xf3, 0x07,
	0x0d, 0xcc, 0xbf, 0xa0, 0x5b, 0x8b, 0xc8, 0x1e, 0x84, 0xac, 0x0a, 0xfa, 0x32, 0xda, 0xee, 0xac,
	0x45, 0x93, 0xab, 0x4d, 0x2a, 0xf8, 0xdf, 0x4b, 0xd3, 0x31, 0xfc, 0x81, 0x6f, 0xc9, 0xe5, 0xf3,
	0xb9, 0xbb, 0x7c, 0xc1, 0x4f, 0xd7, 0xb2, 0x54, 0x7c, 0x8d, 0x59, 0x53, 0x70, 0x49, 0xf9, 0x2a,
	0x27, 0x29, 0x49, 0xad, 0x6c, 0x21, 0xa8, 0x6a, 0x32, 0xc4, 0x3c, 0x49, 0x79, 0xd0, 0xd5, 0x03,
	0x8b, 0xfb, 0x08, 0xfb, 0x51, 0x0b, 0x08, 0x7c, 0x6f, 0x50, 0x1b, 0x16, 0xc2, 0xe0, 0xae, 0xc2,
	0x3a, 0x35, 0x25, 0xa9, 0xe4, 0xb3, 0xc2, 0x91, 0x33, 0x76, 0x26, 0xc3, 0xe9, 0x71, 0xf0, 0xdb,
	0x0c, 0xb6, 0x98, 0xf8, 0x69, 0x30, 0x06, 0xbb, 0x51, 0x6a, 0xd2, 0xd1, 0xce, 0xd8, 0x99, 0xb8,
	0xc2, 0x9e, 0xfd, 0x33, 0x18, 0x6c, 0xc6, 0xe8, 0x8a, 0x94, 0x46, 0x76, 0x08, 0x7d, 0x81, 0xba,
	0x79, 0x33, 0x76, 0x80, 0x2b, 0x36, 0xb7, 0x8b, 0x2b, 0x70, 0xb7, 0xdd, 0xd8, 0x01, 0xec, 0x45,
	0xf1, 0xec, 0xfe, 0x66, 0x19, 0x8b, 0x87, 0x58, 0x78, 0x3d, 0x36, 0x04, 0x58, 0x26, 0xe1, 0x7c,
	0x91, 0x88, 0x70, 0x1e, 0x7b, 0xce, 0xf4, 0x11, 0xc0, 0xb6, 0x0d, 0x0b, 0x54, 0x86, 0x2d, 0xa0,
	0x7f, 0xab, 0x3e, 0xe8, 0x15, 0xd9, 0xc9, 0xdf, 0x75, 0xbf, 0xff, 0xf2, 0xe8, 0xf4, 0xdf, 0xf7,
	0x6e, 0x3d, 0xbf, 0x37, 0xbb, 0x7c, 0x3a, 0x2f, 0x4a, 0xf3, 0xd2, 0x64, 0x2d, 0xc6, 0x65, 0x99,
	0xd7, 0xa4, 0xe9, 0xd9, 0xb4, 0xc9, 0xf2, 0xba, 0xca, 0x79, 0x27, 0x73, 0x2b, 0x67, 0x7d, 0x1b,
	0xef, 0xf5, 0x57, 0x00, 0x00, 0x00, 0xff, 0xff, 0x13, 0xbb, 0x9c, 0xb1, 0x84, 0x01, 0x00, 0x00,
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
