// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_nodeagent_credentialmonitor.proto

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

type CertificateStatus int32

const (
	CertificateStatus_Single  CertificateStatus = 0
	CertificateStatus_Overlap CertificateStatus = 1
)

var CertificateStatus_name = map[int32]string{
	0: "Single",
	1: "Overlap",
}

var CertificateStatus_value = map[string]int32{
	"Single":  0,
	"Overlap": 1,
}

func (x CertificateStatus) String() string {
	return proto.EnumName(CertificateStatus_name, int32(x))
}

func (CertificateStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_dc7a3c9386b615ca, []int{0}
}

type CredentialMonitorRequest struct {
	CredentialMonitor    *CredentialMonitor `protobuf:"bytes,1,opt,name=CredentialMonitor,proto3" json:"CredentialMonitor,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *CredentialMonitorRequest) Reset()         { *m = CredentialMonitorRequest{} }
func (m *CredentialMonitorRequest) String() string { return proto.CompactTextString(m) }
func (*CredentialMonitorRequest) ProtoMessage()    {}
func (*CredentialMonitorRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_dc7a3c9386b615ca, []int{0}
}

func (m *CredentialMonitorRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CredentialMonitorRequest.Unmarshal(m, b)
}
func (m *CredentialMonitorRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CredentialMonitorRequest.Marshal(b, m, deterministic)
}
func (m *CredentialMonitorRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CredentialMonitorRequest.Merge(m, src)
}
func (m *CredentialMonitorRequest) XXX_Size() int {
	return xxx_messageInfo_CredentialMonitorRequest.Size(m)
}
func (m *CredentialMonitorRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CredentialMonitorRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CredentialMonitorRequest proto.InternalMessageInfo

func (m *CredentialMonitorRequest) GetCredentialMonitor() *CredentialMonitor {
	if m != nil {
		return m.CredentialMonitor
	}
	return nil
}

type CredentialMonitorResponse struct {
	CredentialMonitor    *CredentialMonitor `protobuf:"bytes,1,opt,name=CredentialMonitor,proto3" json:"CredentialMonitor,omitempty"`
	Error                string             `protobuf:"bytes,2,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *CredentialMonitorResponse) Reset()         { *m = CredentialMonitorResponse{} }
func (m *CredentialMonitorResponse) String() string { return proto.CompactTextString(m) }
func (*CredentialMonitorResponse) ProtoMessage()    {}
func (*CredentialMonitorResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_dc7a3c9386b615ca, []int{1}
}

func (m *CredentialMonitorResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CredentialMonitorResponse.Unmarshal(m, b)
}
func (m *CredentialMonitorResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CredentialMonitorResponse.Marshal(b, m, deterministic)
}
func (m *CredentialMonitorResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CredentialMonitorResponse.Merge(m, src)
}
func (m *CredentialMonitorResponse) XXX_Size() int {
	return xxx_messageInfo_CredentialMonitorResponse.Size(m)
}
func (m *CredentialMonitorResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CredentialMonitorResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CredentialMonitorResponse proto.InternalMessageInfo

func (m *CredentialMonitorResponse) GetCredentialMonitor() *CredentialMonitor {
	if m != nil {
		return m.CredentialMonitor
	}
	return nil
}

func (m *CredentialMonitorResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type CredentialMonitor struct {
	Certificate          string            `protobuf:"bytes,1,opt,name=certificate,proto3" json:"certificate,omitempty"`
	Status               CertificateStatus `protobuf:"varint,2,opt,name=status,proto3,enum=moc.nodeagent.admin.CertificateStatus" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *CredentialMonitor) Reset()         { *m = CredentialMonitor{} }
func (m *CredentialMonitor) String() string { return proto.CompactTextString(m) }
func (*CredentialMonitor) ProtoMessage()    {}
func (*CredentialMonitor) Descriptor() ([]byte, []int) {
	return fileDescriptor_dc7a3c9386b615ca, []int{2}
}

func (m *CredentialMonitor) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CredentialMonitor.Unmarshal(m, b)
}
func (m *CredentialMonitor) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CredentialMonitor.Marshal(b, m, deterministic)
}
func (m *CredentialMonitor) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CredentialMonitor.Merge(m, src)
}
func (m *CredentialMonitor) XXX_Size() int {
	return xxx_messageInfo_CredentialMonitor.Size(m)
}
func (m *CredentialMonitor) XXX_DiscardUnknown() {
	xxx_messageInfo_CredentialMonitor.DiscardUnknown(m)
}

var xxx_messageInfo_CredentialMonitor proto.InternalMessageInfo

func (m *CredentialMonitor) GetCertificate() string {
	if m != nil {
		return m.Certificate
	}
	return ""
}

func (m *CredentialMonitor) GetStatus() CertificateStatus {
	if m != nil {
		return m.Status
	}
	return CertificateStatus_Single
}

func init() {
	proto.RegisterEnum("moc.nodeagent.admin.CertificateStatus", CertificateStatus_name, CertificateStatus_value)
	proto.RegisterType((*CredentialMonitorRequest)(nil), "moc.nodeagent.admin.CredentialMonitorRequest")
	proto.RegisterType((*CredentialMonitorResponse)(nil), "moc.nodeagent.admin.CredentialMonitorResponse")
	proto.RegisterType((*CredentialMonitor)(nil), "moc.nodeagent.admin.CredentialMonitor")
}

func init() {
	proto.RegisterFile("moc_nodeagent_credentialmonitor.proto", fileDescriptor_dc7a3c9386b615ca)
}

var fileDescriptor_dc7a3c9386b615ca = []byte{
	// 295 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x92, 0xc1, 0x4b, 0x2b, 0x31,
	0x10, 0x87, 0x9b, 0xf7, 0xb0, 0xd2, 0x29, 0x48, 0x1b, 0x45, 0xaa, 0xa7, 0xb2, 0xa0, 0x14, 0xa9,
	0x59, 0xa8, 0x77, 0x41, 0x45, 0x3c, 0x89, 0xb0, 0xf5, 0xe4, 0xa5, 0xa4, 0xe9, 0xb4, 0x06, 0x9a,
	0xcc, 0x9a, 0xcc, 0x7a, 0xf6, 0xe6, 0xbf, 0x2d, 0xee, 0x4a, 0x15, 0x76, 0x85, 0x5e, 0x3c, 0x26,
	0xf3, 0x9b, 0xef, 0x1b, 0x32, 0x81, 0x13, 0x47, 0x66, 0xe6, 0x69, 0x81, 0x7a, 0x85, 0x9e, 0x67,
	0x26, 0xe0, 0x02, 0x3d, 0x5b, 0xbd, 0x76, 0xe4, 0x2d, 0x53, 0x50, 0x79, 0x20, 0x26, 0xb9, 0xef,
	0xc8, 0xa8, 0x4d, 0x4c, 0xe9, 0x85, 0xb3, 0x3e, 0xc9, 0x61, 0x70, 0xb3, 0xc9, 0xdf, 0x57, 0xf9,
	0x0c, 0x5f, 0x0a, 0x8c, 0x2c, 0x1f, 0xa1, 0x5f, 0xab, 0x0d, 0xc4, 0x50, 0x8c, 0xba, 0x93, 0x53,
	0xd5, 0x00, 0x53, 0x75, 0x52, 0x1d, 0x90, 0xbc, 0x0b, 0x38, 0x6a, 0x50, 0xc6, 0x9c, 0x7c, 0xc4,
	0xbf, 0x71, 0xca, 0x03, 0xd8, 0xb9, 0x0d, 0x81, 0xc2, 0xe0, 0xdf, 0x50, 0x8c, 0x3a, 0x59, 0x75,
	0x48, 0x8a, 0x06, 0x97, 0x1c, 0x42, 0xd7, 0x60, 0x60, 0xbb, 0xb4, 0x46, 0x33, 0x96, 0xea, 0x4e,
	0xf6, 0xf3, 0x4a, 0x5e, 0x42, 0x3b, 0xb2, 0xe6, 0x22, 0x96, 0xb4, 0xbd, 0xdf, 0xe6, 0xfa, 0xee,
	0x98, 0x96, 0xe9, 0xec, 0xab, 0xeb, 0x6c, 0x0c, 0xfd, 0x5a, 0x51, 0x02, 0xb4, 0xa7, 0xd6, 0xaf,
	0xd6, 0xd8, 0x6b, 0xc9, 0x2e, 0xec, 0x3e, 0xbc, 0x62, 0x58, 0xeb, 0xbc, 0x27, 0x26, 0x6f, 0x02,
	0x0e, 0x6b, 0x53, 0x5e, 0x7d, 0x8a, 0xe4, 0x12, 0xfe, 0xdf, 0x21, 0xcb, 0xf3, 0x2d, 0xdf, 0xa5,
	0xda, 0xea, 0xb1, 0xda, 0x36, 0x5e, 0x6d, 0x24, 0x69, 0x5d, 0xab, 0xa7, 0xf1, 0xca, 0xf2, 0x73,
	0x31, 0x57, 0x86, 0x5c, 0xea, 0xac, 0x09, 0x14, 0x69, 0xc9, 0xa9, 0x23, 0x93, 0x86, 0xdc, 0xa4,
	0x1b, 0x56, 0x5a, 0xb2, 0xe6, 0xed, 0xf2, 0xbf, 0x5d, 0x7c, 0x04, 0x00, 0x00, 0xff, 0xff, 0x5e,
	0xa8, 0xc6, 0x28, 0x98, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// CredentialMonitorAgentClient is the client API for CredentialMonitorAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CredentialMonitorAgentClient interface {
	Get(ctx context.Context, in *CredentialMonitorRequest, opts ...grpc.CallOption) (*CredentialMonitorResponse, error)
}

type credentialMonitorAgentClient struct {
	cc *grpc.ClientConn
}

func NewCredentialMonitorAgentClient(cc *grpc.ClientConn) CredentialMonitorAgentClient {
	return &credentialMonitorAgentClient{cc}
}

func (c *credentialMonitorAgentClient) Get(ctx context.Context, in *CredentialMonitorRequest, opts ...grpc.CallOption) (*CredentialMonitorResponse, error) {
	out := new(CredentialMonitorResponse)
	err := c.cc.Invoke(ctx, "/moc.nodeagent.admin.CredentialMonitorAgent/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CredentialMonitorAgentServer is the server API for CredentialMonitorAgent service.
type CredentialMonitorAgentServer interface {
	Get(context.Context, *CredentialMonitorRequest) (*CredentialMonitorResponse, error)
}

// UnimplementedCredentialMonitorAgentServer can be embedded to have forward compatible implementations.
type UnimplementedCredentialMonitorAgentServer struct {
}

func (*UnimplementedCredentialMonitorAgentServer) Get(ctx context.Context, req *CredentialMonitorRequest) (*CredentialMonitorResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}

func RegisterCredentialMonitorAgentServer(s *grpc.Server, srv CredentialMonitorAgentServer) {
	s.RegisterService(&_CredentialMonitorAgent_serviceDesc, srv)
}

func _CredentialMonitorAgent_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CredentialMonitorRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CredentialMonitorAgentServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.nodeagent.admin.CredentialMonitorAgent/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CredentialMonitorAgentServer).Get(ctx, req.(*CredentialMonitorRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _CredentialMonitorAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.nodeagent.admin.CredentialMonitorAgent",
	HandlerType: (*CredentialMonitorAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Get",
			Handler:    _CredentialMonitorAgent_Get_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_nodeagent_credentialmonitor.proto",
}
