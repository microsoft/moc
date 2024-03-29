// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_networksecuritygroup.proto

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

type Action int32

const (
	Action_Allow Action = 0
	Action_Deny  Action = 1
)

var Action_name = map[int32]string{
	0: "Allow",
	1: "Deny",
}

var Action_value = map[string]int32{
	"Allow": 0,
	"Deny":  1,
}

func (x Action) String() string {
	return proto.EnumName(Action_name, int32(x))
}

func (Action) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_f7a6eb5efc25ffee, []int{0}
}

type Direction int32

const (
	Direction_Inbound  Direction = 0
	Direction_Outbound Direction = 1
)

var Direction_name = map[int32]string{
	0: "Inbound",
	1: "Outbound",
}

var Direction_value = map[string]int32{
	"Inbound":  0,
	"Outbound": 1,
}

func (x Direction) String() string {
	return proto.EnumName(Direction_name, int32(x))
}

func (Direction) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_f7a6eb5efc25ffee, []int{1}
}

type NetworkSecurityGroupRequest struct {
	NetworkSecurityGroups []*NetworkSecurityGroup `protobuf:"bytes,1,rep,name=NetworkSecurityGroups,proto3" json:"NetworkSecurityGroups,omitempty"`
	OperationType         common.Operation        `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral  struct{}                `json:"-"`
	XXX_unrecognized      []byte                  `json:"-"`
	XXX_sizecache         int32                   `json:"-"`
}

func (m *NetworkSecurityGroupRequest) Reset()         { *m = NetworkSecurityGroupRequest{} }
func (m *NetworkSecurityGroupRequest) String() string { return proto.CompactTextString(m) }
func (*NetworkSecurityGroupRequest) ProtoMessage()    {}
func (*NetworkSecurityGroupRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_f7a6eb5efc25ffee, []int{0}
}

func (m *NetworkSecurityGroupRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NetworkSecurityGroupRequest.Unmarshal(m, b)
}
func (m *NetworkSecurityGroupRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NetworkSecurityGroupRequest.Marshal(b, m, deterministic)
}
func (m *NetworkSecurityGroupRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkSecurityGroupRequest.Merge(m, src)
}
func (m *NetworkSecurityGroupRequest) XXX_Size() int {
	return xxx_messageInfo_NetworkSecurityGroupRequest.Size(m)
}
func (m *NetworkSecurityGroupRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkSecurityGroupRequest.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkSecurityGroupRequest proto.InternalMessageInfo

func (m *NetworkSecurityGroupRequest) GetNetworkSecurityGroups() []*NetworkSecurityGroup {
	if m != nil {
		return m.NetworkSecurityGroups
	}
	return nil
}

func (m *NetworkSecurityGroupRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type NetworkSecurityGroupResponse struct {
	NetworkSecurityGroups []*NetworkSecurityGroup `protobuf:"bytes,1,rep,name=NetworkSecurityGroups,proto3" json:"NetworkSecurityGroups,omitempty"`
	Result                *wrappers.BoolValue     `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                 string                  `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral  struct{}                `json:"-"`
	XXX_unrecognized      []byte                  `json:"-"`
	XXX_sizecache         int32                   `json:"-"`
}

func (m *NetworkSecurityGroupResponse) Reset()         { *m = NetworkSecurityGroupResponse{} }
func (m *NetworkSecurityGroupResponse) String() string { return proto.CompactTextString(m) }
func (*NetworkSecurityGroupResponse) ProtoMessage()    {}
func (*NetworkSecurityGroupResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_f7a6eb5efc25ffee, []int{1}
}

func (m *NetworkSecurityGroupResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NetworkSecurityGroupResponse.Unmarshal(m, b)
}
func (m *NetworkSecurityGroupResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NetworkSecurityGroupResponse.Marshal(b, m, deterministic)
}
func (m *NetworkSecurityGroupResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkSecurityGroupResponse.Merge(m, src)
}
func (m *NetworkSecurityGroupResponse) XXX_Size() int {
	return xxx_messageInfo_NetworkSecurityGroupResponse.Size(m)
}
func (m *NetworkSecurityGroupResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkSecurityGroupResponse.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkSecurityGroupResponse proto.InternalMessageInfo

func (m *NetworkSecurityGroupResponse) GetNetworkSecurityGroups() []*NetworkSecurityGroup {
	if m != nil {
		return m.NetworkSecurityGroups
	}
	return nil
}

func (m *NetworkSecurityGroupResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *NetworkSecurityGroupResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type NetworkSecurityGroupRule struct {
	Name                     string          `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Description              string          `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	Action                   Action          `protobuf:"varint,3,opt,name=action,proto3,enum=moc.cloudagent.network.Action" json:"action,omitempty"`
	Direction                Direction       `protobuf:"varint,4,opt,name=direction,proto3,enum=moc.cloudagent.network.Direction" json:"direction,omitempty"`
	SourceAddressPrefix      string          `protobuf:"bytes,5,opt,name=sourceAddressPrefix,proto3" json:"sourceAddressPrefix,omitempty"`
	DestinationAddressPrefix string          `protobuf:"bytes,6,opt,name=destinationAddressPrefix,proto3" json:"destinationAddressPrefix,omitempty"`
	SourcePortRange          string          `protobuf:"bytes,7,opt,name=sourcePortRange,proto3" json:"sourcePortRange,omitempty"`
	DestinationPortRange     string          `protobuf:"bytes,8,opt,name=destinationPortRange,proto3" json:"destinationPortRange,omitempty"`
	Protocol                 common.Protocol `protobuf:"varint,9,opt,name=protocol,proto3,enum=moc.Protocol" json:"protocol,omitempty"`
	Priority                 uint32          `protobuf:"varint,10,opt,name=priority,proto3" json:"priority,omitempty"`
	Logging                  bool            `protobuf:"varint,11,opt,name=logging,proto3" json:"logging,omitempty"`
	IsDefaultRule            bool            `protobuf:"varint,12,opt,name=isDefaultRule,proto3" json:"isDefaultRule,omitempty"`
	XXX_NoUnkeyedLiteral     struct{}        `json:"-"`
	XXX_unrecognized         []byte          `json:"-"`
	XXX_sizecache            int32           `json:"-"`
}

func (m *NetworkSecurityGroupRule) Reset()         { *m = NetworkSecurityGroupRule{} }
func (m *NetworkSecurityGroupRule) String() string { return proto.CompactTextString(m) }
func (*NetworkSecurityGroupRule) ProtoMessage()    {}
func (*NetworkSecurityGroupRule) Descriptor() ([]byte, []int) {
	return fileDescriptor_f7a6eb5efc25ffee, []int{2}
}

func (m *NetworkSecurityGroupRule) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NetworkSecurityGroupRule.Unmarshal(m, b)
}
func (m *NetworkSecurityGroupRule) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NetworkSecurityGroupRule.Marshal(b, m, deterministic)
}
func (m *NetworkSecurityGroupRule) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkSecurityGroupRule.Merge(m, src)
}
func (m *NetworkSecurityGroupRule) XXX_Size() int {
	return xxx_messageInfo_NetworkSecurityGroupRule.Size(m)
}
func (m *NetworkSecurityGroupRule) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkSecurityGroupRule.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkSecurityGroupRule proto.InternalMessageInfo

func (m *NetworkSecurityGroupRule) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *NetworkSecurityGroupRule) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func (m *NetworkSecurityGroupRule) GetAction() Action {
	if m != nil {
		return m.Action
	}
	return Action_Allow
}

func (m *NetworkSecurityGroupRule) GetDirection() Direction {
	if m != nil {
		return m.Direction
	}
	return Direction_Inbound
}

func (m *NetworkSecurityGroupRule) GetSourceAddressPrefix() string {
	if m != nil {
		return m.SourceAddressPrefix
	}
	return ""
}

func (m *NetworkSecurityGroupRule) GetDestinationAddressPrefix() string {
	if m != nil {
		return m.DestinationAddressPrefix
	}
	return ""
}

func (m *NetworkSecurityGroupRule) GetSourcePortRange() string {
	if m != nil {
		return m.SourcePortRange
	}
	return ""
}

func (m *NetworkSecurityGroupRule) GetDestinationPortRange() string {
	if m != nil {
		return m.DestinationPortRange
	}
	return ""
}

func (m *NetworkSecurityGroupRule) GetProtocol() common.Protocol {
	if m != nil {
		return m.Protocol
	}
	return common.Protocol_All
}

func (m *NetworkSecurityGroupRule) GetPriority() uint32 {
	if m != nil {
		return m.Priority
	}
	return 0
}

func (m *NetworkSecurityGroupRule) GetLogging() bool {
	if m != nil {
		return m.Logging
	}
	return false
}

func (m *NetworkSecurityGroupRule) GetIsDefaultRule() bool {
	if m != nil {
		return m.IsDefaultRule
	}
	return false
}

type NetworkSecurityGroup struct {
	Name                      string                      `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                        string                      `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Networksecuritygrouprules []*NetworkSecurityGroupRule `protobuf:"bytes,3,rep,name=networksecuritygrouprules,proto3" json:"networksecuritygrouprules,omitempty"`
	GroupName                 string                      `protobuf:"bytes,5,opt,name=groupName,proto3" json:"groupName,omitempty"`
	LocationName              string                      `protobuf:"bytes,6,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Status                    *common.Status              `protobuf:"bytes,7,opt,name=status,proto3" json:"status,omitempty"`
	Tags                      *common.Tags                `protobuf:"bytes,8,opt,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral      struct{}                    `json:"-"`
	XXX_unrecognized          []byte                      `json:"-"`
	XXX_sizecache             int32                       `json:"-"`
}

func (m *NetworkSecurityGroup) Reset()         { *m = NetworkSecurityGroup{} }
func (m *NetworkSecurityGroup) String() string { return proto.CompactTextString(m) }
func (*NetworkSecurityGroup) ProtoMessage()    {}
func (*NetworkSecurityGroup) Descriptor() ([]byte, []int) {
	return fileDescriptor_f7a6eb5efc25ffee, []int{3}
}

func (m *NetworkSecurityGroup) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NetworkSecurityGroup.Unmarshal(m, b)
}
func (m *NetworkSecurityGroup) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NetworkSecurityGroup.Marshal(b, m, deterministic)
}
func (m *NetworkSecurityGroup) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetworkSecurityGroup.Merge(m, src)
}
func (m *NetworkSecurityGroup) XXX_Size() int {
	return xxx_messageInfo_NetworkSecurityGroup.Size(m)
}
func (m *NetworkSecurityGroup) XXX_DiscardUnknown() {
	xxx_messageInfo_NetworkSecurityGroup.DiscardUnknown(m)
}

var xxx_messageInfo_NetworkSecurityGroup proto.InternalMessageInfo

func (m *NetworkSecurityGroup) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *NetworkSecurityGroup) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *NetworkSecurityGroup) GetNetworksecuritygrouprules() []*NetworkSecurityGroupRule {
	if m != nil {
		return m.Networksecuritygrouprules
	}
	return nil
}

func (m *NetworkSecurityGroup) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *NetworkSecurityGroup) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *NetworkSecurityGroup) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *NetworkSecurityGroup) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func init() {
	proto.RegisterEnum("moc.cloudagent.network.Action", Action_name, Action_value)
	proto.RegisterEnum("moc.cloudagent.network.Direction", Direction_name, Direction_value)
	proto.RegisterType((*NetworkSecurityGroupRequest)(nil), "moc.cloudagent.network.NetworkSecurityGroupRequest")
	proto.RegisterType((*NetworkSecurityGroupResponse)(nil), "moc.cloudagent.network.NetworkSecurityGroupResponse")
	proto.RegisterType((*NetworkSecurityGroupRule)(nil), "moc.cloudagent.network.NetworkSecurityGroupRule")
	proto.RegisterType((*NetworkSecurityGroup)(nil), "moc.cloudagent.network.NetworkSecurityGroup")
}

func init() {
	proto.RegisterFile("moc_cloudagent_networksecuritygroup.proto", fileDescriptor_f7a6eb5efc25ffee)
}

var fileDescriptor_f7a6eb5efc25ffee = []byte{
	// 698 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x54, 0xcd, 0x4e, 0xdb, 0x4a,
	0x14, 0xc6, 0x49, 0x08, 0xf1, 0x31, 0xe1, 0xa2, 0xb9, 0xdc, 0x7b, 0x4d, 0x2e, 0xa0, 0x34, 0xad,
	0xaa, 0x80, 0x2a, 0x9b, 0x1a, 0xd4, 0x45, 0x37, 0x55, 0x10, 0x55, 0xc5, 0x06, 0xd0, 0x80, 0xba,
	0xe8, 0x06, 0x39, 0xf6, 0xc4, 0xb5, 0xb0, 0x3d, 0xee, 0xfc, 0x94, 0xf2, 0x1a, 0x5d, 0xf7, 0x21,
	0xba, 0xeb, 0x4b, 0xf4, 0xa1, 0x2a, 0x1f, 0x9b, 0xfc, 0x54, 0xce, 0x82, 0x4d, 0x57, 0xc9, 0x39,
	0xdf, 0xf7, 0x9d, 0x39, 0x3e, 0xdf, 0x99, 0x81, 0xfd, 0x94, 0x07, 0x37, 0x41, 0xc2, 0x75, 0xe8,
	0x47, 0x2c, 0x53, 0x37, 0x19, 0x53, 0x77, 0x5c, 0xdc, 0x4a, 0x16, 0x68, 0x11, 0xab, 0xfb, 0x48,
	0x70, 0x9d, 0x3b, 0xb9, 0xe0, 0x8a, 0x93, 0x7f, 0x53, 0x1e, 0x38, 0x33, 0xaa, 0x53, 0x51, 0x7b,
	0x7b, 0x11, 0xe7, 0x51, 0xc2, 0x5c, 0x64, 0x8d, 0xf5, 0xc4, 0xbd, 0x13, 0x7e, 0x9e, 0x33, 0x21,
	0x4b, 0x5d, 0xef, 0x3f, 0x3c, 0x82, 0xa7, 0x29, 0xcf, 0xaa, 0x9f, 0x0a, 0xd8, 0x9b, 0x03, 0xaa,
	0x62, 0xf3, 0xf8, 0xe0, 0x87, 0x01, 0xff, 0x9f, 0x97, 0xf9, 0xab, 0xaa, 0x9f, 0x77, 0x45, 0x3f,
	0x94, 0x7d, 0xd2, 0x4c, 0x2a, 0x32, 0x86, 0x7f, 0xea, 0x60, 0x69, 0x1b, 0xfd, 0xe6, 0xd0, 0xf2,
	0x5e, 0x38, 0xf5, 0x0d, 0x3b, 0xb5, 0x35, 0xeb, 0x4b, 0x91, 0x63, 0xe8, 0x5e, 0xe4, 0x4c, 0xf8,
	0x2a, 0xe6, 0xd9, 0xf5, 0x7d, 0xce, 0xec, 0x46, 0xdf, 0x18, 0x6e, 0x78, 0x1b, 0x58, 0x7b, 0x8a,
	0xd0, 0x45, 0xd2, 0xe0, 0xa7, 0x01, 0x3b, 0xf5, 0x9d, 0xcb, 0x9c, 0x67, 0x92, 0xfd, 0x91, 0xd6,
	0x3d, 0x68, 0x53, 0x26, 0x75, 0xa2, 0xb0, 0x67, 0xcb, 0xeb, 0x39, 0xa5, 0x51, 0xce, 0x83, 0x51,
	0xce, 0x09, 0xe7, 0xc9, 0x7b, 0x3f, 0xd1, 0x8c, 0x56, 0x4c, 0xb2, 0x05, 0xab, 0x6f, 0x85, 0xe0,
	0xc2, 0x6e, 0xf6, 0x8d, 0xa1, 0x49, 0xcb, 0x60, 0xf0, 0xad, 0x05, 0x76, 0xed, 0xc9, 0x3a, 0x61,
	0x84, 0x40, 0x2b, 0xf3, 0x53, 0x66, 0x1b, 0xa8, 0xc0, 0xff, 0xa4, 0x0f, 0x56, 0xc8, 0x64, 0x20,
	0xe2, 0xbc, 0x18, 0x09, 0x9e, 0x6f, 0xd2, 0xf9, 0x14, 0x79, 0x05, 0x6d, 0x3f, 0x40, 0xb0, 0x89,
	0x03, 0xdd, 0x5b, 0xf6, 0xc5, 0x23, 0x64, 0xd1, 0x8a, 0x4d, 0xde, 0x80, 0x19, 0xc6, 0x82, 0x95,
	0xd2, 0x16, 0x4a, 0x9f, 0x2c, 0x93, 0x9e, 0x3e, 0x10, 0xe9, 0x4c, 0x43, 0x0e, 0xe1, 0x6f, 0xc9,
	0xb5, 0x08, 0xd8, 0x28, 0x0c, 0x05, 0x93, 0xf2, 0x52, 0xb0, 0x49, 0xfc, 0xc5, 0x5e, 0xc5, 0x16,
	0xeb, 0x20, 0xf2, 0x1a, 0xec, 0x90, 0x49, 0x15, 0x67, 0xe8, 0xef, 0xa2, 0xac, 0x8d, 0xb2, 0xa5,
	0x38, 0x19, 0xc2, 0x5f, 0x65, 0xc9, 0x4b, 0x2e, 0x14, 0xf5, 0xb3, 0x88, 0xd9, 0x6b, 0x28, 0xf9,
	0x3d, 0x4d, 0x3c, 0xd8, 0x9a, 0xab, 0x32, 0xa3, 0x77, 0x90, 0x5e, 0x8b, 0x91, 0x7d, 0xe8, 0xa0,
	0x97, 0x01, 0x4f, 0x6c, 0x13, 0x67, 0xd1, 0xc5, 0x59, 0x5c, 0x56, 0x49, 0x3a, 0x85, 0x49, 0xaf,
	0xa0, 0xc6, 0xbc, 0xb0, 0xce, 0x86, 0xbe, 0x31, 0xec, 0xd2, 0x69, 0x4c, 0x6c, 0x58, 0x4b, 0x78,
	0x14, 0xc5, 0x59, 0x64, 0x5b, 0x7d, 0x63, 0xd8, 0xa1, 0x0f, 0x21, 0x79, 0x06, 0xdd, 0x58, 0x9e,
	0xb2, 0x89, 0xaf, 0x13, 0x55, 0x98, 0x6d, 0xaf, 0x23, 0xbe, 0x98, 0x1c, 0x7c, 0x6f, 0xc0, 0x56,
	0xdd, 0x7a, 0xd4, 0xae, 0xc6, 0x06, 0x34, 0xe2, 0xb0, 0xda, 0x88, 0x46, 0x1c, 0x92, 0x0c, 0xb6,
	0xeb, 0xde, 0x1c, 0xa1, 0x13, 0x26, 0xed, 0x26, 0xde, 0x86, 0xc3, 0x47, 0xdd, 0x06, 0x9d, 0x30,
	0xba, 0xbc, 0x24, 0xd9, 0x01, 0x13, 0xa3, 0xf3, 0xa2, 0xb1, 0xd2, 0xf5, 0x59, 0x82, 0x0c, 0x60,
	0x3d, 0xe1, 0x01, 0x8e, 0x19, 0x09, 0xa5, 0xbf, 0x0b, 0x39, 0xf2, 0x14, 0xda, 0x52, 0xf9, 0x4a,
	0x4b, 0xb4, 0xd2, 0xf2, 0x2c, 0x6c, 0xef, 0x0a, 0x53, 0xb4, 0x82, 0xc8, 0x2e, 0xb4, 0x94, 0x1f,
	0x49, 0xb4, 0xcf, 0xf2, 0x4c, 0xa4, 0x5c, 0xfb, 0x91, 0xa4, 0x98, 0x3e, 0xd8, 0x85, 0x76, 0xb9,
	0xd8, 0xc4, 0x84, 0xd5, 0x51, 0x92, 0xf0, 0xbb, 0xcd, 0x15, 0xd2, 0x81, 0xd6, 0x29, 0xcb, 0xee,
	0x37, 0x8d, 0x83, 0xe7, 0x60, 0x4e, 0x97, 0x97, 0x58, 0xb0, 0x76, 0x96, 0x8d, 0xb9, 0xce, 0xc2,
	0xcd, 0x15, 0xb2, 0x0e, 0x9d, 0x0b, 0xad, 0xca, 0xc8, 0xf0, 0xbe, 0x1a, 0xb0, 0x5d, 0x37, 0x84,
	0x51, 0x31, 0x26, 0xa2, 0xa1, 0x7d, 0x96, 0x7d, 0xe6, 0xb7, 0x8c, 0x1c, 0x3d, 0x6a, 0x82, 0xe5,
	0xf3, 0xda, 0x3b, 0x7e, 0x9c, 0xa8, 0x7c, 0xd9, 0x06, 0x2b, 0x27, 0x2f, 0x3f, 0xb8, 0x51, 0xac,
	0x3e, 0xea, 0xb1, 0x13, 0xf0, 0xd4, 0x4d, 0xe3, 0x40, 0x70, 0xc9, 0x27, 0xca, 0x4d, 0x79, 0xe0,
	0x8a, 0x3c, 0x70, 0x67, 0x15, 0xdd, 0xaa, 0xe2, 0xb8, 0x8d, 0x7b, 0x7a, 0xf4, 0x2b, 0x00, 0x00,
	0xff, 0xff, 0xab, 0xdf, 0x17, 0xa4, 0x8e, 0x06, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// NetworkSecurityGroupAgentClient is the client API for NetworkSecurityGroupAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type NetworkSecurityGroupAgentClient interface {
	Invoke(ctx context.Context, in *NetworkSecurityGroupRequest, opts ...grpc.CallOption) (*NetworkSecurityGroupResponse, error)
}

type networkSecurityGroupAgentClient struct {
	cc *grpc.ClientConn
}

func NewNetworkSecurityGroupAgentClient(cc *grpc.ClientConn) NetworkSecurityGroupAgentClient {
	return &networkSecurityGroupAgentClient{cc}
}

func (c *networkSecurityGroupAgentClient) Invoke(ctx context.Context, in *NetworkSecurityGroupRequest, opts ...grpc.CallOption) (*NetworkSecurityGroupResponse, error) {
	out := new(NetworkSecurityGroupResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.NetworkSecurityGroupAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NetworkSecurityGroupAgentServer is the server API for NetworkSecurityGroupAgent service.
type NetworkSecurityGroupAgentServer interface {
	Invoke(context.Context, *NetworkSecurityGroupRequest) (*NetworkSecurityGroupResponse, error)
}

// UnimplementedNetworkSecurityGroupAgentServer can be embedded to have forward compatible implementations.
type UnimplementedNetworkSecurityGroupAgentServer struct {
}

func (*UnimplementedNetworkSecurityGroupAgentServer) Invoke(ctx context.Context, req *NetworkSecurityGroupRequest) (*NetworkSecurityGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}

func RegisterNetworkSecurityGroupAgentServer(s *grpc.Server, srv NetworkSecurityGroupAgentServer) {
	s.RegisterService(&_NetworkSecurityGroupAgent_serviceDesc, srv)
}

func _NetworkSecurityGroupAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NetworkSecurityGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkSecurityGroupAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.NetworkSecurityGroupAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkSecurityGroupAgentServer).Invoke(ctx, req.(*NetworkSecurityGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _NetworkSecurityGroupAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.network.NetworkSecurityGroupAgent",
	HandlerType: (*NetworkSecurityGroupAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _NetworkSecurityGroupAgent_Invoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_networksecuritygroup.proto",
}
