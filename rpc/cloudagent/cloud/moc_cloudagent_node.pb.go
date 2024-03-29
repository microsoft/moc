// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_node.proto

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

type NodeState int32

const (
	NodeState_Unknown  NodeState = 0
	NodeState_Active   NodeState = 1
	NodeState_Inactive NodeState = 2
	NodeState_Poweroff NodeState = 3
)

var NodeState_name = map[int32]string{
	0: "Unknown",
	1: "Active",
	2: "Inactive",
	3: "Poweroff",
}

var NodeState_value = map[string]int32{
	"Unknown":  0,
	"Active":   1,
	"Inactive": 2,
	"Poweroff": 3,
}

func (x NodeState) String() string {
	return proto.EnumName(NodeState_name, int32(x))
}

func (NodeState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_b0158d7634fb6fce, []int{0}
}

type NodeRequest struct {
	Nodes                []*Node          `protobuf:"bytes,1,rep,name=Nodes,proto3" json:"Nodes,omitempty"`
	OperationType        common.Operation `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *NodeRequest) Reset()         { *m = NodeRequest{} }
func (m *NodeRequest) String() string { return proto.CompactTextString(m) }
func (*NodeRequest) ProtoMessage()    {}
func (*NodeRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_b0158d7634fb6fce, []int{0}
}

func (m *NodeRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeRequest.Unmarshal(m, b)
}
func (m *NodeRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeRequest.Marshal(b, m, deterministic)
}
func (m *NodeRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeRequest.Merge(m, src)
}
func (m *NodeRequest) XXX_Size() int {
	return xxx_messageInfo_NodeRequest.Size(m)
}
func (m *NodeRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeRequest.DiscardUnknown(m)
}

var xxx_messageInfo_NodeRequest proto.InternalMessageInfo

func (m *NodeRequest) GetNodes() []*Node {
	if m != nil {
		return m.Nodes
	}
	return nil
}

func (m *NodeRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type NodeResponse struct {
	Nodes                []*Node             `protobuf:"bytes,1,rep,name=Nodes,proto3" json:"Nodes,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *NodeResponse) Reset()         { *m = NodeResponse{} }
func (m *NodeResponse) String() string { return proto.CompactTextString(m) }
func (*NodeResponse) ProtoMessage()    {}
func (*NodeResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b0158d7634fb6fce, []int{1}
}

func (m *NodeResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeResponse.Unmarshal(m, b)
}
func (m *NodeResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeResponse.Marshal(b, m, deterministic)
}
func (m *NodeResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeResponse.Merge(m, src)
}
func (m *NodeResponse) XXX_Size() int {
	return xxx_messageInfo_NodeResponse.Size(m)
}
func (m *NodeResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeResponse.DiscardUnknown(m)
}

var xxx_messageInfo_NodeResponse proto.InternalMessageInfo

func (m *NodeResponse) GetNodes() []*Node {
	if m != nil {
		return m.Nodes
	}
	return nil
}

func (m *NodeResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *NodeResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type Node struct {
	Name                 string           `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string           `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Fqdn                 string           `protobuf:"bytes,3,opt,name=fqdn,proto3" json:"fqdn,omitempty"`
	Status               *common.Status   `protobuf:"bytes,4,opt,name=status,proto3" json:"status,omitempty"`
	LocationName         string           `protobuf:"bytes,5,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Certificate          string           `protobuf:"bytes,6,opt,name=certificate,proto3" json:"certificate,omitempty"`
	Port                 int32            `protobuf:"varint,7,opt,name=port,proto3" json:"port,omitempty"`
	AuthorizerPort       int32            `protobuf:"varint,8,opt,name=authorizerPort,proto3" json:"authorizerPort,omitempty"`
	RunningState         NodeState        `protobuf:"varint,9,opt,name=runningState,proto3,enum=moc.cloudagent.node.NodeState" json:"runningState,omitempty"`
	Info                 *common.NodeInfo `protobuf:"bytes,10,opt,name=info,proto3" json:"info,omitempty"`
	Tags                 *common.Tags     `protobuf:"bytes,11,opt,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *Node) Reset()         { *m = Node{} }
func (m *Node) String() string { return proto.CompactTextString(m) }
func (*Node) ProtoMessage()    {}
func (*Node) Descriptor() ([]byte, []int) {
	return fileDescriptor_b0158d7634fb6fce, []int{2}
}

func (m *Node) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Node.Unmarshal(m, b)
}
func (m *Node) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Node.Marshal(b, m, deterministic)
}
func (m *Node) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Node.Merge(m, src)
}
func (m *Node) XXX_Size() int {
	return xxx_messageInfo_Node.Size(m)
}
func (m *Node) XXX_DiscardUnknown() {
	xxx_messageInfo_Node.DiscardUnknown(m)
}

var xxx_messageInfo_Node proto.InternalMessageInfo

func (m *Node) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Node) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Node) GetFqdn() string {
	if m != nil {
		return m.Fqdn
	}
	return ""
}

func (m *Node) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *Node) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *Node) GetCertificate() string {
	if m != nil {
		return m.Certificate
	}
	return ""
}

func (m *Node) GetPort() int32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *Node) GetAuthorizerPort() int32 {
	if m != nil {
		return m.AuthorizerPort
	}
	return 0
}

func (m *Node) GetRunningState() NodeState {
	if m != nil {
		return m.RunningState
	}
	return NodeState_Unknown
}

func (m *Node) GetInfo() *common.NodeInfo {
	if m != nil {
		return m.Info
	}
	return nil
}

func (m *Node) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func init() {
	proto.RegisterEnum("moc.cloudagent.node.NodeState", NodeState_name, NodeState_value)
	proto.RegisterType((*NodeRequest)(nil), "moc.cloudagent.node.NodeRequest")
	proto.RegisterType((*NodeResponse)(nil), "moc.cloudagent.node.NodeResponse")
	proto.RegisterType((*Node)(nil), "moc.cloudagent.node.Node")
}

func init() { proto.RegisterFile("moc_cloudagent_node.proto", fileDescriptor_b0158d7634fb6fce) }

var fileDescriptor_b0158d7634fb6fce = []byte{
	// 537 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x52, 0xd1, 0x6a, 0xdb, 0x4a,
	0x10, 0x8d, 0x6c, 0x59, 0x89, 0x47, 0xbe, 0xc6, 0xec, 0x0d, 0x54, 0x36, 0x34, 0xb8, 0x2e, 0x04,
	0x53, 0xa8, 0x04, 0x6e, 0x3f, 0xa0, 0x31, 0xf4, 0xc1, 0x2f, 0x49, 0xd8, 0xa6, 0x7d, 0x28, 0x85,
	0x20, 0x4b, 0x2b, 0x45, 0x44, 0xda, 0x51, 0x56, 0xab, 0x98, 0xf6, 0x0b, 0xda, 0x0f, 0xea, 0xbf,
	0xf5, 0xb1, 0xec, 0xac, 0x9b, 0xc4, 0xa5, 0x29, 0xf4, 0x49, 0x33, 0x73, 0xce, 0x99, 0x99, 0x1d,
	0x1d, 0x18, 0x57, 0x98, 0x5c, 0x26, 0x25, 0xb6, 0x69, 0x9c, 0x0b, 0xa9, 0x2f, 0x25, 0xa6, 0x22,
	0xac, 0x15, 0x6a, 0x64, 0xff, 0x57, 0x98, 0x84, 0xf7, 0x50, 0x68, 0xa0, 0xc9, 0x51, 0x8e, 0x98,
	0x97, 0x22, 0x22, 0xca, 0xba, 0xcd, 0xa2, 0x8d, 0x8a, 0xeb, 0x5a, 0xa8, 0xc6, 0x8a, 0x26, 0x4f,
	0xa8, 0x1f, 0x56, 0x15, 0xca, 0xed, 0x67, 0x0b, 0x8c, 0x1f, 0x00, 0xa6, 0x53, 0x21, 0x33, 0xb4,
	0xd0, 0x4c, 0x83, 0x7f, 0x8a, 0xa9, 0xe0, 0xe2, 0xa6, 0x15, 0x8d, 0x66, 0x11, 0xf4, 0x4c, 0xda,
	0x04, 0xce, 0xb4, 0x3b, 0xf7, 0x17, 0xe3, 0xf0, 0x0f, 0x7b, 0x84, 0x24, 0xb0, 0x3c, 0xf6, 0x1a,
	0xfe, 0x3b, 0xab, 0x85, 0x8a, 0x75, 0x81, 0xf2, 0xe2, 0x73, 0x2d, 0x82, 0xce, 0xd4, 0x99, 0x0f,
	0x17, 0x43, 0x12, 0xde, 0x21, 0x7c, 0x97, 0x34, 0xfb, 0xe6, 0xc0, 0xc0, 0x8e, 0x6d, 0x6a, 0x94,
	0x8d, 0xf8, 0xf7, 0xb9, 0x0b, 0xf0, 0xb8, 0x68, 0xda, 0x52, 0xd3, 0x40, 0x7f, 0x31, 0x09, 0xed,
	0x71, 0xc2, 0x5f, 0xc7, 0x09, 0x97, 0x88, 0xe5, 0x87, 0xb8, 0x6c, 0x05, 0xdf, 0x32, 0xd9, 0x21,
	0xf4, 0xde, 0x2a, 0x85, 0x2a, 0xe8, 0x4e, 0x9d, 0x79, 0x9f, 0xdb, 0x64, 0xf6, 0xa3, 0x03, 0xae,
	0xe9, 0xc9, 0x18, 0xb8, 0x32, 0xae, 0x44, 0xe0, 0x10, 0x4a, 0x31, 0x1b, 0x42, 0xa7, 0x48, 0x69,
	0x44, 0x9f, 0x77, 0x8a, 0xd4, 0x70, 0xb2, 0x9b, 0x54, 0x6e, 0x3b, 0x50, 0xcc, 0x9e, 0x83, 0xd7,
	0xe8, 0x58, 0xb7, 0x4d, 0xe0, 0xd2, 0x2a, 0x3e, 0x2d, 0xff, 0x8e, 0x4a, 0x7c, 0x0b, 0xb1, 0x19,
	0x0c, 0x4a, 0x4c, 0xe8, 0x02, 0xa7, 0x66, 0x48, 0x8f, 0x1a, 0xec, 0xd4, 0xd8, 0x31, 0xf8, 0x89,
	0x50, 0xba, 0xc8, 0x8a, 0x24, 0xd6, 0x22, 0xf0, 0x0c, 0x65, 0xe9, 0x7e, 0xfd, 0x1e, 0x38, 0xfc,
	0x21, 0x60, 0x96, 0xa8, 0x51, 0xe9, 0x60, 0x7f, 0xea, 0xcc, 0x7b, 0x9c, 0x62, 0x76, 0x0c, 0xc3,
	0xb8, 0xd5, 0x57, 0xa8, 0x8a, 0x2f, 0x42, 0x9d, 0x1b, 0xf4, 0x80, 0xd0, 0xdf, 0xaa, 0x6c, 0x09,
	0x03, 0xd5, 0x4a, 0x59, 0xc8, 0xdc, 0x2c, 0x28, 0x82, 0x3e, 0xfd, 0xae, 0xa3, 0x47, 0xef, 0x4d,
	0x2c, 0xbe, 0xa3, 0x61, 0x73, 0x70, 0x8d, 0x83, 0x02, 0xa0, 0xe7, 0x1e, 0x5a, 0xad, 0xf5, 0x9b,
	0x91, 0xac, 0x64, 0x86, 0x9c, 0x18, 0xec, 0x29, 0xb8, 0x3a, 0xce, 0x9b, 0xc0, 0x27, 0x66, 0x9f,
	0x98, 0x17, 0x71, 0xde, 0x70, 0x2a, 0xbf, 0x78, 0x03, 0xfd, 0xbb, 0x19, 0xcc, 0x87, 0xfd, 0xf7,
	0xf2, 0x5a, 0xe2, 0x46, 0x8e, 0xf6, 0x18, 0x80, 0x77, 0x92, 0xe8, 0xe2, 0x56, 0x8c, 0x1c, 0x36,
	0x80, 0x83, 0x95, 0x8c, 0x6d, 0xd6, 0x31, 0xd9, 0x39, 0x6e, 0x84, 0xc2, 0x2c, 0x1b, 0x75, 0x17,
	0x9f, 0x6c, 0x87, 0x13, 0xb3, 0x34, 0x3b, 0x03, 0x6f, 0x25, 0x6f, 0xf1, 0x5a, 0xb0, 0xe9, 0xe3,
	0xfe, 0xb1, 0x46, 0x9f, 0x3c, 0xfb, 0x0b, 0xc3, 0x7a, 0x72, 0xb6, 0xb7, 0x8c, 0x3e, 0xbe, 0xcc,
	0x0b, 0x7d, 0xd5, 0xae, 0xcd, 0xf3, 0xa2, 0xaa, 0x48, 0x14, 0x36, 0x98, 0xe9, 0xa8, 0xc2, 0x24,
	0x52, 0x75, 0x12, 0xdd, 0xcb, 0x6d, 0xb8, 0xf6, 0xc8, 0x7d, 0xaf, 0x7e, 0x06, 0x00, 0x00, 0xff,
	0xff, 0xfc, 0x00, 0x45, 0xc7, 0xda, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// NodeAgentClient is the client API for NodeAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type NodeAgentClient interface {
	Invoke(ctx context.Context, in *NodeRequest, opts ...grpc.CallOption) (*NodeResponse, error)
}

type nodeAgentClient struct {
	cc *grpc.ClientConn
}

func NewNodeAgentClient(cc *grpc.ClientConn) NodeAgentClient {
	return &nodeAgentClient{cc}
}

func (c *nodeAgentClient) Invoke(ctx context.Context, in *NodeRequest, opts ...grpc.CallOption) (*NodeResponse, error) {
	out := new(NodeResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.node.NodeAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NodeAgentServer is the server API for NodeAgent service.
type NodeAgentServer interface {
	Invoke(context.Context, *NodeRequest) (*NodeResponse, error)
}

// UnimplementedNodeAgentServer can be embedded to have forward compatible implementations.
type UnimplementedNodeAgentServer struct {
}

func (*UnimplementedNodeAgentServer) Invoke(ctx context.Context, req *NodeRequest) (*NodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}

func RegisterNodeAgentServer(s *grpc.Server, srv NodeAgentServer) {
	s.RegisterService(&_NodeAgent_serviceDesc, srv)
}

func _NodeAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.node.NodeAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeAgentServer).Invoke(ctx, req.(*NodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _NodeAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.node.NodeAgent",
	HandlerType: (*NodeAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _NodeAgent_Invoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_node.proto",
}
