// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_etcdcluster.proto

package cloud

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

type EtcdClusterRequest struct {
	EtcdClusters         []*EtcdCluster   `protobuf:"bytes,1,rep,name=EtcdClusters,proto3" json:"EtcdClusters,omitempty"`
	OperationType        common.Operation `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *EtcdClusterRequest) Reset()         { *m = EtcdClusterRequest{} }
func (m *EtcdClusterRequest) String() string { return proto.CompactTextString(m) }
func (*EtcdClusterRequest) ProtoMessage()    {}
func (*EtcdClusterRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8d73c226ba9892c4, []int{0}
}

func (m *EtcdClusterRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EtcdClusterRequest.Unmarshal(m, b)
}
func (m *EtcdClusterRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EtcdClusterRequest.Marshal(b, m, deterministic)
}
func (m *EtcdClusterRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EtcdClusterRequest.Merge(m, src)
}
func (m *EtcdClusterRequest) XXX_Size() int {
	return xxx_messageInfo_EtcdClusterRequest.Size(m)
}
func (m *EtcdClusterRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_EtcdClusterRequest.DiscardUnknown(m)
}

var xxx_messageInfo_EtcdClusterRequest proto.InternalMessageInfo

func (m *EtcdClusterRequest) GetEtcdClusters() []*EtcdCluster {
	if m != nil {
		return m.EtcdClusters
	}
	return nil
}

func (m *EtcdClusterRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type EtcdClusterResponse struct {
	EtcdClusters         []*EtcdCluster      `protobuf:"bytes,1,rep,name=EtcdClusters,proto3" json:"EtcdClusters,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *EtcdClusterResponse) Reset()         { *m = EtcdClusterResponse{} }
func (m *EtcdClusterResponse) String() string { return proto.CompactTextString(m) }
func (*EtcdClusterResponse) ProtoMessage()    {}
func (*EtcdClusterResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8d73c226ba9892c4, []int{1}
}

func (m *EtcdClusterResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EtcdClusterResponse.Unmarshal(m, b)
}
func (m *EtcdClusterResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EtcdClusterResponse.Marshal(b, m, deterministic)
}
func (m *EtcdClusterResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EtcdClusterResponse.Merge(m, src)
}
func (m *EtcdClusterResponse) XXX_Size() int {
	return xxx_messageInfo_EtcdClusterResponse.Size(m)
}
func (m *EtcdClusterResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_EtcdClusterResponse.DiscardUnknown(m)
}

var xxx_messageInfo_EtcdClusterResponse proto.InternalMessageInfo

func (m *EtcdClusterResponse) GetEtcdClusters() []*EtcdCluster {
	if m != nil {
		return m.EtcdClusters
	}
	return nil
}

func (m *EtcdClusterResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *EtcdClusterResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type EtcdCluster struct {
	Id           string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name         string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	LocationName string `protobuf:"bytes,3,opt,name=locationName,proto3" json:"locationName,omitempty"`
	GroupName    string `protobuf:"bytes,4,opt,name=groupName,proto3" json:"groupName,omitempty"`
	// etcd ca certificate that works as RoT for client and peer connections
	CaCertificate string `protobuf:"bytes,5,opt,name=caCertificate,proto3" json:"caCertificate,omitempty"`
	// etcd ca key associated with the ca certificate
	CaKey                string         `protobuf:"bytes,6,opt,name=caKey,proto3" json:"caKey,omitempty"`
	Status               *common.Status `protobuf:"bytes,7,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *EtcdCluster) Reset()         { *m = EtcdCluster{} }
func (m *EtcdCluster) String() string { return proto.CompactTextString(m) }
func (*EtcdCluster) ProtoMessage()    {}
func (*EtcdCluster) Descriptor() ([]byte, []int) {
	return fileDescriptor_8d73c226ba9892c4, []int{2}
}

func (m *EtcdCluster) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EtcdCluster.Unmarshal(m, b)
}
func (m *EtcdCluster) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EtcdCluster.Marshal(b, m, deterministic)
}
func (m *EtcdCluster) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EtcdCluster.Merge(m, src)
}
func (m *EtcdCluster) XXX_Size() int {
	return xxx_messageInfo_EtcdCluster.Size(m)
}
func (m *EtcdCluster) XXX_DiscardUnknown() {
	xxx_messageInfo_EtcdCluster.DiscardUnknown(m)
}

var xxx_messageInfo_EtcdCluster proto.InternalMessageInfo

func (m *EtcdCluster) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *EtcdCluster) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *EtcdCluster) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *EtcdCluster) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *EtcdCluster) GetCaCertificate() string {
	if m != nil {
		return m.CaCertificate
	}
	return ""
}

func (m *EtcdCluster) GetCaKey() string {
	if m != nil {
		return m.CaKey
	}
	return ""
}

func (m *EtcdCluster) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func init() {
	proto.RegisterType((*EtcdClusterRequest)(nil), "moc.cloudagent.etcd.EtcdClusterRequest")
	proto.RegisterType((*EtcdClusterResponse)(nil), "moc.cloudagent.etcd.EtcdClusterResponse")
	proto.RegisterType((*EtcdCluster)(nil), "moc.cloudagent.etcd.EtcdCluster")
}

func init() { proto.RegisterFile("moc_cloudagent_etcdcluster.proto", fileDescriptor_8d73c226ba9892c4) }

var fileDescriptor_8d73c226ba9892c4 = []byte{
	// 430 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x92, 0xdf, 0x8a, 0xd3, 0x40,
	0x14, 0xc6, 0x4d, 0xb7, 0x8d, 0xf4, 0x74, 0xb7, 0xc8, 0xac, 0x60, 0x08, 0x22, 0x21, 0x5e, 0x58,
	0x04, 0x27, 0x10, 0x7d, 0x01, 0xbb, 0xee, 0x85, 0x08, 0x0a, 0x51, 0xbc, 0x10, 0x64, 0x99, 0x4e,
	0x4e, 0x63, 0x30, 0xc9, 0xc9, 0xce, 0x1f, 0x65, 0xdf, 0xc0, 0x4b, 0x5f, 0xc2, 0x47, 0xf0, 0x7d,
	0x7c, 0x14, 0xe9, 0x4c, 0xb5, 0x09, 0x08, 0xbd, 0xf1, 0xaa, 0xd3, 0xf3, 0xfd, 0xce, 0x37, 0xe7,
	0x7c, 0x13, 0x48, 0x5a, 0x92, 0x57, 0xb2, 0x21, 0x5b, 0x8a, 0x0a, 0x3b, 0x73, 0x85, 0x46, 0x96,
	0xb2, 0xb1, 0xda, 0xa0, 0xe2, 0xbd, 0x22, 0x43, 0xec, 0xbc, 0x25, 0xc9, 0x0f, 0x04, 0xdf, 0x11,
	0xf1, 0x83, 0x8a, 0xa8, 0x6a, 0x30, 0x73, 0xc8, 0xc6, 0x6e, 0xb3, 0xaf, 0x4a, 0xf4, 0x3d, 0x2a,
	0xed, 0x9b, 0xe2, 0x7b, 0xce, 0x96, 0xda, 0x96, 0xba, 0xfd, 0x8f, 0x17, 0xd2, 0xef, 0x01, 0xb0,
	0x4b, 0x23, 0xcb, 0x0b, 0x7f, 0x47, 0x81, 0xd7, 0x16, 0xb5, 0x61, 0x2f, 0xe0, 0x74, 0x50, 0xd5,
	0x51, 0x90, 0x9c, 0xac, 0x16, 0x79, 0xc2, 0xff, 0x71, 0x37, 0x1f, 0xb6, 0x8f, 0xba, 0xd8, 0x33,
	0x38, 0x7b, 0xd3, 0xa3, 0x12, 0xa6, 0xa6, 0xee, 0xdd, 0x4d, 0x8f, 0xd1, 0x24, 0x09, 0x56, 0xcb,
	0x7c, 0xe9, 0x6c, 0xfe, 0x2a, 0xc5, 0x18, 0x4a, 0x7f, 0x04, 0x70, 0x3e, 0x1a, 0x49, 0xf7, 0xd4,
	0x69, 0xfc, 0x4f, 0x33, 0xe5, 0x10, 0x16, 0xa8, 0x6d, 0x63, 0xdc, 0x30, 0x8b, 0x3c, 0xe6, 0x3e,
	0x3a, 0xfe, 0x27, 0x3a, 0xbe, 0x26, 0x6a, 0xde, 0x8b, 0xc6, 0x62, 0xb1, 0x27, 0xd9, 0x5d, 0x98,
	0x5d, 0x2a, 0x45, 0x2a, 0x3a, 0x49, 0x82, 0xd5, 0xbc, 0xf0, 0x7f, 0xd2, 0x5f, 0x01, 0x2c, 0x06,
	0xd6, 0x6c, 0x09, 0x93, 0xba, 0x8c, 0x02, 0x87, 0x4c, 0xea, 0x92, 0x31, 0x98, 0x76, 0xa2, 0xf5,
	0x4b, 0xcf, 0x0b, 0x77, 0x66, 0x29, 0x9c, 0x36, 0x24, 0xdd, 0xae, 0xaf, 0x77, 0x9a, 0x37, 0x1c,
	0xd5, 0xd8, 0x7d, 0x98, 0x57, 0x8a, 0x6c, 0xef, 0x80, 0xa9, 0x03, 0x0e, 0x05, 0xf6, 0x18, 0xce,
	0xa4, 0xb8, 0x40, 0x65, 0xea, 0x6d, 0x2d, 0x85, 0xc1, 0x68, 0xb6, 0x23, 0xd6, 0xd3, 0x6f, 0x3f,
	0xa3, 0xa0, 0x18, 0x4b, 0x2c, 0x86, 0x99, 0x14, 0xaf, 0xf0, 0x26, 0x0a, 0x07, 0x8c, 0x2f, 0xb1,
	0x87, 0x10, 0x6a, 0x23, 0x8c, 0xd5, 0xd1, 0x6d, 0x97, 0xc3, 0xc2, 0xe5, 0xf8, 0xd6, 0x95, 0x8a,
	0xbd, 0x94, 0x5f, 0xc3, 0x9d, 0xc1, 0x86, 0xcf, 0x77, 0xf9, 0xb2, 0x8f, 0x10, 0xbe, 0xec, 0xbe,
	0xd0, 0x67, 0x64, 0x8f, 0x8e, 0x46, 0xef, 0xbf, 0xa6, 0x78, 0x75, 0x1c, 0xf4, 0x6f, 0x9c, 0xde,
	0x5a, 0x67, 0x1f, 0x9e, 0x54, 0xb5, 0xf9, 0x64, 0x37, 0x5c, 0x52, 0x9b, 0xb5, 0xb5, 0x54, 0xa4,
	0x69, 0x6b, 0xb2, 0x96, 0x64, 0xa6, 0x7a, 0x99, 0x1d, 0x5c, 0xfc, 0x71, 0x13, 0xba, 0x87, 0x7b,
	0xfa, 0x3b, 0x00, 0x00, 0xff, 0xff, 0x41, 0xe7, 0xd5, 0xeb, 0x3a, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// EtcdClusterAgentClient is the client API for EtcdClusterAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type EtcdClusterAgentClient interface {
	Invoke(ctx context.Context, in *EtcdClusterRequest, opts ...grpc.CallOption) (*EtcdClusterResponse, error)
}

type etcdClusterAgentClient struct {
	cc *grpc.ClientConn
}

func NewEtcdClusterAgentClient(cc *grpc.ClientConn) EtcdClusterAgentClient {
	return &etcdClusterAgentClient{cc}
}

func (c *etcdClusterAgentClient) Invoke(ctx context.Context, in *EtcdClusterRequest, opts ...grpc.CallOption) (*EtcdClusterResponse, error) {
	out := new(EtcdClusterResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.etcd.EtcdClusterAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EtcdClusterAgentServer is the server API for EtcdClusterAgent service.
type EtcdClusterAgentServer interface {
	Invoke(context.Context, *EtcdClusterRequest) (*EtcdClusterResponse, error)
}

// UnimplementedEtcdClusterAgentServer can be embedded to have forward compatible implementations.
type UnimplementedEtcdClusterAgentServer struct {
}

func (*UnimplementedEtcdClusterAgentServer) Invoke(ctx context.Context, req *EtcdClusterRequest) (*EtcdClusterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}

func RegisterEtcdClusterAgentServer(s *grpc.Server, srv EtcdClusterAgentServer) {
	s.RegisterService(&_EtcdClusterAgent_serviceDesc, srv)
}

func _EtcdClusterAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EtcdClusterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EtcdClusterAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.etcd.EtcdClusterAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EtcdClusterAgentServer).Invoke(ctx, req.(*EtcdClusterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _EtcdClusterAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.etcd.EtcdClusterAgent",
	HandlerType: (*EtcdClusterAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _EtcdClusterAgent_Invoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_etcdcluster.proto",
}
