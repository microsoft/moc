// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_virtualmachineimage.proto

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

type VirtualMachineImageRequest struct {
	VirtualMachineImages []*VirtualMachineImage `protobuf:"bytes,1,rep,name=VirtualMachineImages,proto3" json:"VirtualMachineImages,omitempty"`
	OperationType        common.Operation       `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *VirtualMachineImageRequest) Reset()         { *m = VirtualMachineImageRequest{} }
func (m *VirtualMachineImageRequest) String() string { return proto.CompactTextString(m) }
func (*VirtualMachineImageRequest) ProtoMessage()    {}
func (*VirtualMachineImageRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_7ef669fbb27720b1, []int{0}
}

func (m *VirtualMachineImageRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualMachineImageRequest.Unmarshal(m, b)
}
func (m *VirtualMachineImageRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualMachineImageRequest.Marshal(b, m, deterministic)
}
func (m *VirtualMachineImageRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualMachineImageRequest.Merge(m, src)
}
func (m *VirtualMachineImageRequest) XXX_Size() int {
	return xxx_messageInfo_VirtualMachineImageRequest.Size(m)
}
func (m *VirtualMachineImageRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualMachineImageRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualMachineImageRequest proto.InternalMessageInfo

func (m *VirtualMachineImageRequest) GetVirtualMachineImages() []*VirtualMachineImage {
	if m != nil {
		return m.VirtualMachineImages
	}
	return nil
}

func (m *VirtualMachineImageRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type VirtualMachineImageResponse struct {
	VirtualMachineImages []*VirtualMachineImage `protobuf:"bytes,1,rep,name=VirtualMachineImages,proto3" json:"VirtualMachineImages,omitempty"`
	Result               *wrappers.BoolValue    `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string                 `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *VirtualMachineImageResponse) Reset()         { *m = VirtualMachineImageResponse{} }
func (m *VirtualMachineImageResponse) String() string { return proto.CompactTextString(m) }
func (*VirtualMachineImageResponse) ProtoMessage()    {}
func (*VirtualMachineImageResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_7ef669fbb27720b1, []int{1}
}

func (m *VirtualMachineImageResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualMachineImageResponse.Unmarshal(m, b)
}
func (m *VirtualMachineImageResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualMachineImageResponse.Marshal(b, m, deterministic)
}
func (m *VirtualMachineImageResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualMachineImageResponse.Merge(m, src)
}
func (m *VirtualMachineImageResponse) XXX_Size() int {
	return xxx_messageInfo_VirtualMachineImageResponse.Size(m)
}
func (m *VirtualMachineImageResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualMachineImageResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualMachineImageResponse proto.InternalMessageInfo

func (m *VirtualMachineImageResponse) GetVirtualMachineImages() []*VirtualMachineImage {
	if m != nil {
		return m.VirtualMachineImages
	}
	return nil
}

func (m *VirtualMachineImageResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *VirtualMachineImageResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type VirtualMachineImage struct {
	Name                 string                     `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string                     `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	ImageReference       string                     `protobuf:"bytes,3,opt,name=imageReference,proto3" json:"imageReference,omitempty"`
	Path                 string                     `protobuf:"bytes,4,opt,name=path,proto3" json:"path,omitempty"`
	Status               *common.Status             `protobuf:"bytes,5,opt,name=status,proto3" json:"status,omitempty"`
	ContainerName        string                     `protobuf:"bytes,6,opt,name=containerName,proto3" json:"containerName,omitempty"`
	GroupName            string                     `protobuf:"bytes,18,opt,name=groupName,proto3" json:"groupName,omitempty"`
	LocationName         string                     `protobuf:"bytes,19,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Tags                 *common.Tags               `protobuf:"bytes,20,opt,name=tags,proto3" json:"tags,omitempty"`
	CloudInitDataSource  common.CloudInitDataSource `protobuf:"varint,22,opt,name=cloudInitDataSource,proto3,enum=moc.CloudInitDataSource" json:"cloudInitDataSource,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *VirtualMachineImage) Reset()         { *m = VirtualMachineImage{} }
func (m *VirtualMachineImage) String() string { return proto.CompactTextString(m) }
func (*VirtualMachineImage) ProtoMessage()    {}
func (*VirtualMachineImage) Descriptor() ([]byte, []int) {
	return fileDescriptor_7ef669fbb27720b1, []int{2}
}

func (m *VirtualMachineImage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualMachineImage.Unmarshal(m, b)
}
func (m *VirtualMachineImage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualMachineImage.Marshal(b, m, deterministic)
}
func (m *VirtualMachineImage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualMachineImage.Merge(m, src)
}
func (m *VirtualMachineImage) XXX_Size() int {
	return xxx_messageInfo_VirtualMachineImage.Size(m)
}
func (m *VirtualMachineImage) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualMachineImage.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualMachineImage proto.InternalMessageInfo

func (m *VirtualMachineImage) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *VirtualMachineImage) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *VirtualMachineImage) GetImageReference() string {
	if m != nil {
		return m.ImageReference
	}
	return ""
}

func (m *VirtualMachineImage) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *VirtualMachineImage) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *VirtualMachineImage) GetContainerName() string {
	if m != nil {
		return m.ContainerName
	}
	return ""
}

func (m *VirtualMachineImage) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *VirtualMachineImage) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *VirtualMachineImage) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func (m *VirtualMachineImage) GetCloudInitDataSource() common.CloudInitDataSource {
	if m != nil {
		return m.CloudInitDataSource
	}
	return common.CloudInitDataSource_NoCloud
}

func init() {
	proto.RegisterType((*VirtualMachineImageRequest)(nil), "moc.cloudagent.compute.VirtualMachineImageRequest")
	proto.RegisterType((*VirtualMachineImageResponse)(nil), "moc.cloudagent.compute.VirtualMachineImageResponse")
	proto.RegisterType((*VirtualMachineImage)(nil), "moc.cloudagent.compute.VirtualMachineImage")
}

func init() {
	proto.RegisterFile("moc_cloudagent_virtualmachineimage.proto", fileDescriptor_7ef669fbb27720b1)
}

var fileDescriptor_7ef669fbb27720b1 = []byte{
	// 493 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x53, 0x4b, 0x8e, 0xd3, 0x40,
	0x10, 0xc5, 0x99, 0x99, 0x48, 0xe9, 0x30, 0x59, 0x74, 0xa2, 0xc1, 0x0a, 0x1f, 0x45, 0x01, 0xa1,
	0x48, 0x48, 0xb6, 0xf0, 0x70, 0x01, 0x06, 0x58, 0x04, 0x09, 0x90, 0x3c, 0xa3, 0x59, 0xb0, 0x89,
	0x3a, 0x9d, 0x8a, 0xd3, 0xc2, 0xee, 0x32, 0xfd, 0x19, 0xc4, 0x29, 0x38, 0x0c, 0x97, 0xe0, 0x32,
	0xdc, 0x01, 0xb9, 0xda, 0x10, 0x05, 0xbc, 0x99, 0x05, 0xab, 0x74, 0x5e, 0xbd, 0x7a, 0xef, 0x75,
	0x57, 0x99, 0x2d, 0x2a, 0x94, 0x2b, 0x59, 0xa2, 0xdf, 0x88, 0x02, 0xb4, 0x5b, 0xdd, 0x28, 0xe3,
	0xbc, 0x28, 0x2b, 0x21, 0x77, 0x4a, 0x83, 0xaa, 0x44, 0x01, 0x49, 0x6d, 0xd0, 0x21, 0x3f, 0xab,
	0x50, 0x26, 0x7b, 0x66, 0x22, 0xb1, 0xaa, 0xbd, 0x83, 0xe9, 0xa3, 0x02, 0xb1, 0x28, 0x21, 0x25,
	0xd6, 0xda, 0x6f, 0xd3, 0x2f, 0x46, 0xd4, 0x35, 0x18, 0x1b, 0xfa, 0xa6, 0xf7, 0xc8, 0x01, 0xab,
	0x0a, 0x75, 0xfb, 0x13, 0x0a, 0xf3, 0xef, 0x11, 0x9b, 0x5e, 0x07, 0xbb, 0x77, 0xc1, 0x6e, 0xd9,
	0xd8, 0xe5, 0xf0, 0xd9, 0x83, 0x75, 0x7c, 0xc5, 0x26, 0x1d, 0x55, 0x1b, 0x47, 0xb3, 0xa3, 0xc5,
	0x30, 0x7b, 0x96, 0x74, 0xc7, 0x49, 0xba, 0x14, 0x3b, 0x85, 0xf8, 0x0b, 0x76, 0xfa, 0xa1, 0x06,
	0x23, 0x9c, 0x42, 0x7d, 0xf5, 0xb5, 0x86, 0xb8, 0x37, 0x8b, 0x16, 0xa3, 0x6c, 0x44, 0xca, 0x7f,
	0x2a, 0xf9, 0x21, 0x69, 0xfe, 0x23, 0x62, 0xf7, 0x3b, 0x53, 0xdb, 0x1a, 0xb5, 0x85, 0xff, 0x1f,
	0x3b, 0x63, 0xfd, 0x1c, 0xac, 0x2f, 0x1d, 0xe5, 0x1d, 0x66, 0xd3, 0x24, 0x0c, 0x20, 0xf9, 0x3d,
	0x80, 0xe4, 0x02, 0xb1, 0xbc, 0x16, 0xa5, 0x87, 0xbc, 0x65, 0xf2, 0x09, 0x3b, 0x79, 0x63, 0x0c,
	0x9a, 0xf8, 0x68, 0x16, 0x2d, 0x06, 0x79, 0xf8, 0x33, 0xff, 0xd9, 0x63, 0xe3, 0x0e, 0x0b, 0xce,
	0xd9, 0xb1, 0x16, 0x15, 0xc4, 0x11, 0x91, 0xe9, 0xcc, 0x47, 0xac, 0xa7, 0x36, 0xe4, 0x38, 0xc8,
	0x7b, 0x6a, 0xc3, 0x9f, 0xb2, 0x91, 0x0a, 0xf7, 0xde, 0x82, 0x01, 0x2d, 0xa1, 0x95, 0xfe, 0x0b,
	0x6d, 0xb4, 0x6a, 0xe1, 0x76, 0xf1, 0x71, 0xd0, 0x6a, 0xce, 0xfc, 0x31, 0xeb, 0x5b, 0x27, 0x9c,
	0xb7, 0xf1, 0x09, 0xdd, 0x60, 0x48, 0x8f, 0x72, 0x49, 0x50, 0xde, 0x96, 0xf8, 0x13, 0x76, 0x2a,
	0x51, 0x3b, 0xa1, 0x34, 0x98, 0xf7, 0x4d, 0x9a, 0x3e, 0x29, 0x1c, 0x82, 0xfc, 0x01, 0x1b, 0x14,
	0x06, 0x7d, 0x4d, 0x0c, 0x4e, 0x8c, 0x3d, 0xc0, 0xe7, 0xec, 0x6e, 0x89, 0x92, 0x66, 0x47, 0x84,
	0x31, 0x11, 0x0e, 0x30, 0xfe, 0x90, 0x1d, 0x3b, 0x51, 0xd8, 0x78, 0x42, 0x51, 0x06, 0x14, 0xe5,
	0x4a, 0x14, 0x36, 0x27, 0x98, 0xbf, 0x65, 0x63, 0x9a, 0xd6, 0x52, 0x2b, 0xf7, 0x5a, 0x38, 0x71,
	0x89, 0xde, 0x48, 0x88, 0xcf, 0x68, 0x55, 0x62, 0x62, 0xbf, 0xfa, 0xb7, 0x9e, 0x77, 0x35, 0x65,
	0xdf, 0x22, 0x16, 0x77, 0xbc, 0xf7, 0xcb, 0x66, 0x11, 0xb8, 0x65, 0xfd, 0xa5, 0xbe, 0xc1, 0x4f,
	0xc0, 0xb3, 0xdb, 0xec, 0x48, 0xf8, 0x58, 0xa6, 0xe7, 0xb7, 0xea, 0x09, 0xab, 0x3a, 0xbf, 0x73,
	0xf1, 0xfc, 0x63, 0x5a, 0x28, 0xb7, 0xf3, 0xeb, 0x86, 0x9f, 0x56, 0x4a, 0x1a, 0xb4, 0xb8, 0x75,
	0x69, 0x85, 0x32, 0x35, 0xb5, 0x4c, 0xf7, 0x82, 0x69, 0x2b, 0xb8, 0xee, 0xd3, 0x9a, 0x9d, 0xff,
	0x0a, 0x00, 0x00, 0xff, 0xff, 0xf1, 0x5e, 0xd6, 0x9e, 0x39, 0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// VirtualMachineImageAgentClient is the client API for VirtualMachineImageAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type VirtualMachineImageAgentClient interface {
	Invoke(ctx context.Context, in *VirtualMachineImageRequest, opts ...grpc.CallOption) (*VirtualMachineImageResponse, error)
}

type virtualMachineImageAgentClient struct {
	cc *grpc.ClientConn
}

func NewVirtualMachineImageAgentClient(cc *grpc.ClientConn) VirtualMachineImageAgentClient {
	return &virtualMachineImageAgentClient{cc}
}

func (c *virtualMachineImageAgentClient) Invoke(ctx context.Context, in *VirtualMachineImageRequest, opts ...grpc.CallOption) (*VirtualMachineImageResponse, error) {
	out := new(VirtualMachineImageResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.compute.VirtualMachineImageAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VirtualMachineImageAgentServer is the server API for VirtualMachineImageAgent service.
type VirtualMachineImageAgentServer interface {
	Invoke(context.Context, *VirtualMachineImageRequest) (*VirtualMachineImageResponse, error)
}

// UnimplementedVirtualMachineImageAgentServer can be embedded to have forward compatible implementations.
type UnimplementedVirtualMachineImageAgentServer struct {
}

func (*UnimplementedVirtualMachineImageAgentServer) Invoke(ctx context.Context, req *VirtualMachineImageRequest) (*VirtualMachineImageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}

func RegisterVirtualMachineImageAgentServer(s *grpc.Server, srv VirtualMachineImageAgentServer) {
	s.RegisterService(&_VirtualMachineImageAgent_serviceDesc, srv)
}

func _VirtualMachineImageAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VirtualMachineImageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VirtualMachineImageAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.compute.VirtualMachineImageAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VirtualMachineImageAgentServer).Invoke(ctx, req.(*VirtualMachineImageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _VirtualMachineImageAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.compute.VirtualMachineImageAgent",
	HandlerType: (*VirtualMachineImageAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _VirtualMachineImageAgent_Invoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_virtualmachineimage.proto",
}
