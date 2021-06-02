// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_container.proto

package storage

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

type ContainerType int32

const (
	ContainerType_UNKNOWN ContainerType = 0
	ContainerType_SAN     ContainerType = 1
	ContainerType_CSV     ContainerType = 2
	ContainerType_SMB     ContainerType = 3
	ContainerType_DAS     ContainerType = 4
)

var ContainerType_name = map[int32]string{
	0: "UNKNOWN",
	1: "SAN",
	2: "CSV",
	3: "SMB",
	4: "DAS",
}

var ContainerType_value = map[string]int32{
	"UNKNOWN": 0,
	"SAN":     1,
	"CSV":     2,
	"SMB":     3,
	"DAS":     4,
}

func (x ContainerType) String() string {
	return proto.EnumName(ContainerType_name, int32(x))
}

func (ContainerType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_736e2a9bece4cac4, []int{0}
}

type ContainerRequest struct {
	Containers           []*Container     `protobuf:"bytes,1,rep,name=Containers,proto3" json:"Containers,omitempty"`
	OperationType        common.Operation `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *ContainerRequest) Reset()         { *m = ContainerRequest{} }
func (m *ContainerRequest) String() string { return proto.CompactTextString(m) }
func (*ContainerRequest) ProtoMessage()    {}
func (*ContainerRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_736e2a9bece4cac4, []int{0}
}

func (m *ContainerRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContainerRequest.Unmarshal(m, b)
}
func (m *ContainerRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContainerRequest.Marshal(b, m, deterministic)
}
func (m *ContainerRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContainerRequest.Merge(m, src)
}
func (m *ContainerRequest) XXX_Size() int {
	return xxx_messageInfo_ContainerRequest.Size(m)
}
func (m *ContainerRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ContainerRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ContainerRequest proto.InternalMessageInfo

func (m *ContainerRequest) GetContainers() []*Container {
	if m != nil {
		return m.Containers
	}
	return nil
}

func (m *ContainerRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type ContainerResponse struct {
	Containers           []*Container        `protobuf:"bytes,1,rep,name=Containers,proto3" json:"Containers,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *ContainerResponse) Reset()         { *m = ContainerResponse{} }
func (m *ContainerResponse) String() string { return proto.CompactTextString(m) }
func (*ContainerResponse) ProtoMessage()    {}
func (*ContainerResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_736e2a9bece4cac4, []int{1}
}

func (m *ContainerResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContainerResponse.Unmarshal(m, b)
}
func (m *ContainerResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContainerResponse.Marshal(b, m, deterministic)
}
func (m *ContainerResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContainerResponse.Merge(m, src)
}
func (m *ContainerResponse) XXX_Size() int {
	return xxx_messageInfo_ContainerResponse.Size(m)
}
func (m *ContainerResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ContainerResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ContainerResponse proto.InternalMessageInfo

func (m *ContainerResponse) GetContainers() []*Container {
	if m != nil {
		return m.Containers
	}
	return nil
}

func (m *ContainerResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *ContainerResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type Container struct {
	Name                 string                       `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string                       `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Path                 string                       `protobuf:"bytes,4,opt,name=path,proto3" json:"path,omitempty"`
	Status               *common.Status               `protobuf:"bytes,5,opt,name=status,proto3" json:"status,omitempty"`
	LocationName         string                       `protobuf:"bytes,6,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Info                 *common.StorageContainerInfo `protobuf:"bytes,7,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *Container) Reset()         { *m = Container{} }
func (m *Container) String() string { return proto.CompactTextString(m) }
func (*Container) ProtoMessage()    {}
func (*Container) Descriptor() ([]byte, []int) {
	return fileDescriptor_736e2a9bece4cac4, []int{2}
}

func (m *Container) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Container.Unmarshal(m, b)
}
func (m *Container) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Container.Marshal(b, m, deterministic)
}
func (m *Container) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Container.Merge(m, src)
}
func (m *Container) XXX_Size() int {
	return xxx_messageInfo_Container.Size(m)
}
func (m *Container) XXX_DiscardUnknown() {
	xxx_messageInfo_Container.DiscardUnknown(m)
}

var xxx_messageInfo_Container proto.InternalMessageInfo

func (m *Container) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Container) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Container) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *Container) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *Container) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *Container) GetInfo() *common.StorageContainerInfo {
	if m != nil {
		return m.Info
	}
	return nil
}

func init() {
	proto.RegisterEnum("moc.cloudagent.storage.ContainerType", ContainerType_name, ContainerType_value)
	proto.RegisterType((*ContainerRequest)(nil), "moc.cloudagent.storage.ContainerRequest")
	proto.RegisterType((*ContainerResponse)(nil), "moc.cloudagent.storage.ContainerResponse")
	proto.RegisterType((*Container)(nil), "moc.cloudagent.storage.Container")
}

func init() { proto.RegisterFile("moc_cloudagent_container.proto", fileDescriptor_736e2a9bece4cac4) }

var fileDescriptor_736e2a9bece4cac4 = []byte{
	// 465 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x52, 0xd1, 0x8a, 0xd3, 0x40,
	0x14, 0xdd, 0xb4, 0xdd, 0x94, 0xde, 0xba, 0x25, 0x0e, 0xa2, 0xb1, 0xc8, 0x52, 0xe3, 0x4b, 0x15,
	0x9c, 0x60, 0xf4, 0x03, 0x6c, 0x57, 0x1f, 0x16, 0x31, 0x0b, 0xa9, 0xae, 0xe0, 0x4b, 0x99, 0x4e,
	0xa7, 0xd9, 0x60, 0x32, 0x37, 0x3b, 0x33, 0x51, 0xfc, 0x06, 0x7f, 0xc2, 0xff, 0xf0, 0xe7, 0x24,
	0x93, 0x6c, 0xda, 0x05, 0x41, 0x1f, 0x7c, 0xca, 0xcd, 0x39, 0x67, 0xce, 0x9c, 0x9c, 0x1b, 0x38,
	0x2d, 0x90, 0xaf, 0x79, 0x8e, 0xd5, 0x96, 0xa5, 0x42, 0x9a, 0x35, 0x47, 0x69, 0x58, 0x26, 0x85,
	0xa2, 0xa5, 0x42, 0x83, 0xe4, 0x7e, 0x81, 0x9c, 0xee, 0x79, 0xaa, 0x0d, 0x2a, 0x96, 0x8a, 0xe9,
	0x69, 0x8a, 0x98, 0xe6, 0x22, 0xb4, 0xaa, 0x4d, 0xb5, 0x0b, 0xbf, 0x29, 0x56, 0x96, 0x42, 0xe9,
	0xe6, 0xdc, 0xf4, 0x81, 0xf5, 0xc5, 0xa2, 0x40, 0xd9, 0x3e, 0x5a, 0xe2, 0xd1, 0x01, 0xd1, 0x9a,
	0x65, 0x72, 0x87, 0x0d, 0x1b, 0xfc, 0x70, 0xc0, 0x3b, 0xbb, 0x89, 0x90, 0x88, 0xeb, 0x4a, 0x68,
	0x43, 0x16, 0x00, 0x1d, 0xa6, 0x7d, 0x67, 0xd6, 0x9f, 0x8f, 0xa3, 0xc7, 0xf4, 0xcf, 0xc1, 0xe8,
	0xfe, 0xf4, 0xc1, 0x21, 0xf2, 0x0a, 0x4e, 0x2e, 0x4a, 0xa1, 0x98, 0xc9, 0x50, 0x7e, 0xf8, 0x5e,
	0x0a, 0xbf, 0x37, 0x73, 0xe6, 0x93, 0x68, 0x62, 0x5d, 0x3a, 0x26, 0xb9, 0x2d, 0x0a, 0x7e, 0x3a,
	0x70, 0xf7, 0x20, 0x8d, 0x2e, 0x51, 0x6a, 0xf1, 0x3f, 0xe2, 0x44, 0xe0, 0x26, 0x42, 0x57, 0xb9,
	0xb1, 0x39, 0xc6, 0xd1, 0x94, 0x36, 0x75, 0xd2, 0x9b, 0x3a, 0xe9, 0x12, 0x31, 0xbf, 0x64, 0x79,
	0x25, 0x92, 0x56, 0x49, 0xee, 0xc1, 0xf1, 0x5b, 0xa5, 0x50, 0xf9, 0xfd, 0x99, 0x33, 0x1f, 0x25,
	0xcd, 0x4b, 0xf0, 0xcb, 0x81, 0x51, 0x67, 0x4c, 0x08, 0x0c, 0x24, 0x2b, 0x84, 0xef, 0x58, 0x89,
	0x9d, 0xc9, 0x04, 0x7a, 0xd9, 0xd6, 0xde, 0x33, 0x4a, 0x7a, 0xd9, 0xb6, 0xd6, 0x94, 0xcc, 0x5c,
	0xf9, 0x83, 0x46, 0x53, 0xcf, 0xe4, 0x09, 0xb8, 0xda, 0x30, 0x53, 0x69, 0xff, 0xd8, 0xe6, 0x19,
	0xdb, 0xcf, 0x59, 0x59, 0x28, 0x69, 0x29, 0x12, 0xc0, 0x9d, 0x1c, 0xb9, 0x6d, 0x27, 0xae, 0x2f,
	0x71, 0xad, 0xc1, 0x2d, 0x8c, 0x3c, 0x87, 0x41, 0xbd, 0x4d, 0x7f, 0x68, 0x6d, 0x1e, 0xb6, 0x36,
	0xb6, 0x8a, 0x2e, 0xe5, 0xb9, 0xdc, 0x61, 0x62, 0x65, 0xcf, 0x5e, 0xc3, 0x49, 0x07, 0xd7, 0x8d,
	0x93, 0x31, 0x0c, 0x3f, 0xc6, 0xef, 0xe2, 0x8b, 0x4f, 0xb1, 0x77, 0x44, 0x86, 0xd0, 0x5f, 0x2d,
	0x62, 0xcf, 0xa9, 0x87, 0xb3, 0xd5, 0xa5, 0xd7, 0xb3, 0xc8, 0xfb, 0xa5, 0xd7, 0xaf, 0x87, 0x37,
	0x8b, 0x95, 0x37, 0x88, 0xae, 0x61, 0xd2, 0x39, 0x2c, 0xea, 0xe6, 0xc9, 0x1a, 0xdc, 0x73, 0xf9,
	0x15, 0xbf, 0x08, 0x32, 0xff, 0xfb, 0x52, 0x9a, 0x3f, 0x6c, 0xfa, 0xf4, 0x1f, 0x94, 0xcd, 0xf6,
	0x83, 0xa3, 0xe5, 0x8b, 0xcf, 0x61, 0x9a, 0x99, 0xab, 0x6a, 0x43, 0x39, 0x16, 0x61, 0x91, 0x71,
	0x85, 0x1a, 0x77, 0x26, 0x2c, 0x90, 0x87, 0xaa, 0xe4, 0xe1, 0xde, 0x26, 0x6c, 0x6d, 0x36, 0xae,
	0xdd, 0xeb, 0xcb, 0xdf, 0x01, 0x00, 0x00, 0xff, 0xff, 0x5a, 0x67, 0x0b, 0xc9, 0x6e, 0x03, 0x00,
	0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ContainerAgentClient is the client API for ContainerAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ContainerAgentClient interface {
	Invoke(ctx context.Context, in *ContainerRequest, opts ...grpc.CallOption) (*ContainerResponse, error)
}

type containerAgentClient struct {
	cc *grpc.ClientConn
}

func NewContainerAgentClient(cc *grpc.ClientConn) ContainerAgentClient {
	return &containerAgentClient{cc}
}

func (c *containerAgentClient) Invoke(ctx context.Context, in *ContainerRequest, opts ...grpc.CallOption) (*ContainerResponse, error) {
	out := new(ContainerResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.storage.ContainerAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ContainerAgentServer is the server API for ContainerAgent service.
type ContainerAgentServer interface {
	Invoke(context.Context, *ContainerRequest) (*ContainerResponse, error)
}

// UnimplementedContainerAgentServer can be embedded to have forward compatible implementations.
type UnimplementedContainerAgentServer struct {
}

func (*UnimplementedContainerAgentServer) Invoke(ctx context.Context, req *ContainerRequest) (*ContainerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}

func RegisterContainerAgentServer(s *grpc.Server, srv ContainerAgentServer) {
	s.RegisterService(&_ContainerAgent_serviceDesc, srv)
}

func _ContainerAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ContainerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainerAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.storage.ContainerAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainerAgentServer).Invoke(ctx, req.(*ContainerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _ContainerAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.storage.ContainerAgent",
	HandlerType: (*ContainerAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _ContainerAgent_Invoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_container.proto",
}
