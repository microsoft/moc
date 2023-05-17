// Code generated by protoc-gen-go. DO NOT EDIT.
// source: tls_test.proto

package testagent

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

type Hello struct {
	Name                 string   `protobuf:"bytes,1,opt,name=Name,proto3" json:"Name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Hello) Reset()         { *m = Hello{} }
func (m *Hello) String() string { return proto.CompactTextString(m) }
func (*Hello) ProtoMessage()    {}
func (*Hello) Descriptor() ([]byte, []int) {
	return fileDescriptor_d532ee5fff61f1da, []int{0}
}

func (m *Hello) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Hello.Unmarshal(m, b)
}
func (m *Hello) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Hello.Marshal(b, m, deterministic)
}
func (m *Hello) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Hello.Merge(m, src)
}
func (m *Hello) XXX_Size() int {
	return xxx_messageInfo_Hello.Size(m)
}
func (m *Hello) XXX_DiscardUnknown() {
	xxx_messageInfo_Hello.DiscardUnknown(m)
}

var xxx_messageInfo_Hello proto.InternalMessageInfo

func (m *Hello) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func init() {
	proto.RegisterType((*Hello)(nil), "testagent.Hello")
}

func init() { proto.RegisterFile("tls_test.proto", fileDescriptor_d532ee5fff61f1da) }

var fileDescriptor_d532ee5fff61f1da = []byte{
	// 144 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2b, 0xc9, 0x29, 0x8e,
	0x2f, 0x49, 0x2d, 0x2e, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x04, 0xb1, 0x13, 0xd3,
	0x53, 0xf3, 0x4a, 0x94, 0xa4, 0xb9, 0x58, 0x3d, 0x52, 0x73, 0x72, 0xf2, 0x85, 0x84, 0xb8, 0x58,
	0xfc, 0x12, 0x73, 0x53, 0x25, 0x18, 0x15, 0x18, 0x35, 0x38, 0x83, 0xc0, 0x6c, 0x23, 0x5b, 0x2e,
	0x2e, 0xb0, 0xa4, 0x23, 0x48, 0xa9, 0x90, 0x3e, 0x17, 0x67, 0x40, 0x66, 0x5e, 0x3a, 0x44, 0xb9,
	0x80, 0x1e, 0xdc, 0x0c, 0x3d, 0xb0, 0x88, 0x14, 0x86, 0x88, 0x93, 0x46, 0x94, 0x5a, 0x7a, 0x66,
	0x49, 0x46, 0x69, 0x92, 0x5e, 0x72, 0x7e, 0xae, 0x7e, 0x6e, 0x66, 0x72, 0x51, 0x7e, 0x71, 0x7e,
	0x5a, 0x89, 0x7e, 0x6e, 0x7e, 0xb2, 0x7e, 0x51, 0x41, 0xb2, 0x3e, 0x5c, 0x7d, 0x12, 0x1b, 0xd8,
	0x5d, 0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x9b, 0x17, 0xa3, 0x1b, 0xa9, 0x00, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// HelloAgentClient is the client API for HelloAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type HelloAgentClient interface {
	PingHello(ctx context.Context, in *Hello, opts ...grpc.CallOption) (*Hello, error)
}

type helloAgentClient struct {
	cc *grpc.ClientConn
}

func NewHelloAgentClient(cc *grpc.ClientConn) HelloAgentClient {
	return &helloAgentClient{cc}
}

func (c *helloAgentClient) PingHello(ctx context.Context, in *Hello, opts ...grpc.CallOption) (*Hello, error) {
	out := new(Hello)
	err := c.cc.Invoke(ctx, "/testagent.HelloAgent/PingHello", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HelloAgentServer is the server API for HelloAgent service.
type HelloAgentServer interface {
	PingHello(context.Context, *Hello) (*Hello, error)
}

// UnimplementedHelloAgentServer can be embedded to have forward compatible implementations.
type UnimplementedHelloAgentServer struct {
}

func (*UnimplementedHelloAgentServer) PingHello(ctx context.Context, req *Hello) (*Hello, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PingHello not implemented")
}

func RegisterHelloAgentServer(s *grpc.Server, srv HelloAgentServer) {
	s.RegisterService(&_HelloAgent_serviceDesc, srv)
}

func _HelloAgent_PingHello_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Hello)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HelloAgentServer).PingHello(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/testagent.HelloAgent/PingHello",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HelloAgentServer).PingHello(ctx, req.(*Hello))
	}
	return interceptor(ctx, in, info, handler)
}

var _HelloAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "testagent.HelloAgent",
	HandlerType: (*HelloAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PingHello",
			Handler:    _HelloAgent_PingHello_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "tls_test.proto",
}