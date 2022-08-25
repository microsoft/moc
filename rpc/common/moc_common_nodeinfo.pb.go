// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_common_nodeinfo.proto

package common

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

type OperatingSystemInfo struct {
	OperatingSystemSKU   uint64   `protobuf:"varint,1,opt,name=operatingsystemsku,proto3" json:"operatingsystemsku,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *OperatingSystemInfo) Reset()         { *m = OperatingSystemInfo{} }
func (m *OperatingSystemInfo) String() string { return proto.CompactTextString(m) }
func (*OperatingSystemInfo) ProtoMessage()    {}
func (*OperatingSystemInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{0}
}

func (m *OperatingSystemInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OperatingSystemInfo.Unmarshal(m, b)
}
func (m *OperatingSystemInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OperatingSystemInfo.Marshal(b, m, deterministic)
}
func (m *OperatingSystemInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OperatingSystemInfo.Merge(m, src)
}
func (m *OperatingSystemInfo) XXX_Size() int {
	return xxx_messageInfo_OperatingSystemInfo.Size(m)
}
func (m *OperatingSystemInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_OperatingSystemInfo.DiscardUnknown(m)
}

var xxx_messageInfo_OperatingSystemInfo proto.InternalMessageInfo

type Processor struct {
	Name                 string        `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Cores                uint32        `protobuf:"varint,2,opt,name=cores,proto3" json:"cores,omitempty"`
	Speed                string        `protobuf:"bytes,3,opt,name=speed,proto3" json:"speed,omitempty"`
	Type                 ProcessorType `protobuf:"varint,4,opt,name=type,proto3,enum=moc.ProcessorType" json:"type,omitempty"`
	Virtualization       bool          `protobuf:"varint,5,opt,name=virtualization,proto3" json:"virtualization,omitempty"`
	Logicalprocessors    uint32        `protobuf:"varint,6,opt,name=logicalprocessors,proto3" json:"logicalprocessors,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *Processor) Reset()         { *m = Processor{} }
func (m *Processor) String() string { return proto.CompactTextString(m) }
func (*Processor) ProtoMessage()    {}
func (*Processor) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{0}
}

func (m *Processor) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Processor.Unmarshal(m, b)
}
func (m *Processor) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Processor.Marshal(b, m, deterministic)
}
func (m *Processor) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Processor.Merge(m, src)
}
func (m *Processor) XXX_Size() int {
	return xxx_messageInfo_Processor.Size(m)
}
func (m *Processor) XXX_DiscardUnknown() {
	xxx_messageInfo_Processor.DiscardUnknown(m)
}

var xxx_messageInfo_Processor proto.InternalMessageInfo

func (m *Processor) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Processor) GetCores() uint32 {
	if m != nil {
		return m.Cores
	}
	return 0
}

func (m *Processor) GetSpeed() string {
	if m != nil {
		return m.Speed
	}
	return ""
}

func (m *Processor) GetType() ProcessorType {
	if m != nil {
		return m.Type
	}
	return ProcessorType_None
}

func (m *Processor) GetVirtualization() bool {
	if m != nil {
		return m.Virtualization
	}
	return false
}

func (m *Processor) GetLogicalprocessors() uint32 {
	if m != nil {
		return m.Logicalprocessors
	}
	return 0
}

type PhysicalMemory struct {
	SizeBytes            uint64   `protobuf:"varint,1,opt,name=sizeBytes,proto3" json:"sizeBytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PhysicalMemory) Reset()         { *m = PhysicalMemory{} }
func (m *PhysicalMemory) String() string { return proto.CompactTextString(m) }
func (*PhysicalMemory) ProtoMessage()    {}
func (*PhysicalMemory) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{1}
}

func (m *PhysicalMemory) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PhysicalMemory.Unmarshal(m, b)
}
func (m *PhysicalMemory) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PhysicalMemory.Marshal(b, m, deterministic)
}
func (m *PhysicalMemory) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PhysicalMemory.Merge(m, src)
}
func (m *PhysicalMemory) XXX_Size() int {
	return xxx_messageInfo_PhysicalMemory.Size(m)
}
func (m *PhysicalMemory) XXX_DiscardUnknown() {
	xxx_messageInfo_PhysicalMemory.DiscardUnknown(m)
}

var xxx_messageInfo_PhysicalMemory proto.InternalMessageInfo

func (m *PhysicalMemory) GetSizeBytes() uint64 {
	if m != nil {
		return m.SizeBytes
	}
	return 0
}

type GPU struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	SizeBytes            uint32   `protobuf:"varint,2,opt,name=sizeBytes,proto3" json:"sizeBytes,omitempty"`
	Count                uint32   `protobuf:"varint,3,opt,name=count,proto3" json:"count,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GPU) Reset()         { *m = GPU{} }
func (m *GPU) String() string { return proto.CompactTextString(m) }
func (*GPU) ProtoMessage()    {}
func (*GPU) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{2}
}

func (m *GPU) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GPU.Unmarshal(m, b)
}
func (m *GPU) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GPU.Marshal(b, m, deterministic)
}
func (m *GPU) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GPU.Merge(m, src)
}
func (m *GPU) XXX_Size() int {
	return xxx_messageInfo_GPU.Size(m)
}
func (m *GPU) XXX_DiscardUnknown() {
	xxx_messageInfo_GPU.DiscardUnknown(m)
}

var xxx_messageInfo_GPU proto.InternalMessageInfo

func (m *GPU) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *GPU) GetSizeBytes() uint32 {
	if m != nil {
		return m.SizeBytes
	}
	return 0
}

func (m *GPU) GetCount() uint32 {
	if m != nil {
		return m.Count
	}
	return 0
}

type NodeInfo struct {
	Name                 string              `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string              `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Capability           *Resources          `protobuf:"bytes,3,opt,name=capability,proto3" json:"capability,omitempty"`
	Availability         *Resources          `protobuf:"bytes,4,opt,name=availability,proto3" json:"availability,omitempty"`
	Ostype               OperatingSystemType `protobuf:"varint,6,opt,name=ostype,proto3,enum=moc.OperatingSystemType" json:"ostype,omitempty"`
	Status               *Status             `protobuf:"bytes,7,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *NodeInfo) Reset()         { *m = NodeInfo{} }
func (m *NodeInfo) String() string { return proto.CompactTextString(m) }
func (*NodeInfo) ProtoMessage()    {}
func (*NodeInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{3}
}

func (m *NodeInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeInfo.Unmarshal(m, b)
}
func (m *NodeInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeInfo.Marshal(b, m, deterministic)
}
func (m *NodeInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeInfo.Merge(m, src)
}
func (m *NodeInfo) XXX_Size() int {
	return xxx_messageInfo_NodeInfo.Size(m)
}
func (m *NodeInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeInfo.DiscardUnknown(m)
}

var xxx_messageInfo_NodeInfo proto.InternalMessageInfo

func (m *NodeInfo) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *NodeInfo) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *NodeInfo) GetCapability() *Resources {
	if m != nil {
		return m.Capability
	}
	return nil
}

func (m *NodeInfo) GetAvailability() *Resources {
	if m != nil {
		return m.Availability
	}
	return nil
}

func (m *NodeInfo) GetOstype() OperatingSystemType {
	if m != nil {
		return m.Ostype
	}
	return OperatingSystemType_WINDOWS
}

func (m *NodeInfo) GetStatus() *Status {
	if m != nil {
		return m.Status
	}
	return nil
}

type Resources struct {
	Processor            *Processor           `protobuf:"bytes,1,opt,name=processor,proto3" json:"processor,omitempty"`
	Memory               *PhysicalMemory      `protobuf:"bytes,2,opt,name=memory,proto3" json:"memory,omitempty"`
	Gpu                  *GPU                 `protobuf:"bytes,3,opt,name=gpu,proto3" json:"gpu,omitempty"`
	OperatingSystemInfo  *OperatingSystemInfo `protobuf:"bytes,4,opt,name=osInfo,proto3" json:"osInfo,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *Resources) Reset()         { *m = Resources{} }
func (m *Resources) String() string { return proto.CompactTextString(m) }
func (*Resources) ProtoMessage()    {}
func (*Resources) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{4}
}

func (m *Resources) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Resources.Unmarshal(m, b)
}
func (m *Resources) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Resources.Marshal(b, m, deterministic)
}
func (m *Resources) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Resources.Merge(m, src)
}
func (m *Resources) XXX_Size() int {
	return xxx_messageInfo_Resources.Size(m)
}
func (m *Resources) XXX_DiscardUnknown() {
	xxx_messageInfo_Resources.DiscardUnknown(m)
}

var xxx_messageInfo_Resources proto.InternalMessageInfo

func (m *Resources) GetProcessor() *Processor {
	if m != nil {
		return m.Processor
	}
	return nil
}

func (m *Resources) GetMemory() *PhysicalMemory {
	if m != nil {
		return m.Memory
	}
	return nil
}

func (m *Resources) GetGpu() *GPU {
	if m != nil {
		return m.Gpu
	}
	return nil
}

func (m *Resources) GetOperatingSystemInfo() *OperatingSystemInfo {
	if m != nil {
		return m.OperatingSystemInfo
	}
	return nil
}

func init() {
	proto.RegisterType((*Processor)(nil), "moc.common.Processor")
	proto.RegisterType((*PhysicalMemory)(nil), "moc.common.PhysicalMemory")
	proto.RegisterType((*GPU)(nil), "moc.common.GPU")
	proto.RegisterType((*OperatingSystemInfo)(nil), "moc.common.OperatingSystemInfo")
	proto.RegisterType((*NodeInfo)(nil), "moc.common.NodeInfo")
	proto.RegisterType((*Resources)(nil), "moc.common.Resources")
}

func init() { proto.RegisterFile("moc_common_nodeinfo.proto", fileDescriptor_7c83f03f7e6831a3) }

var fileDescriptor_7c83f03f7e6831a3 = []byte{
	// 469 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x53, 0x4f, 0x6f, 0xd3, 0x30,
	0x14, 0x57, 0xd6, 0x2e, 0x2c, 0xaf, 0x50, 0x84, 0x05, 0x22, 0x54, 0x08, 0x95, 0x4e, 0x4c, 0x3d,
	0xa0, 0x14, 0x75, 0xe2, 0xc0, 0x75, 0x97, 0x89, 0xc3, 0xa0, 0xf2, 0xd8, 0x85, 0xcb, 0xe4, 0x3a,
	0x6e, 0x67, 0x29, 0xce, 0xb3, 0x6c, 0x67, 0x52, 0xf6, 0x45, 0xf8, 0x4c, 0x7c, 0x22, 0xae, 0x28,
	0x2f, 0x5d, 0xdb, 0x8c, 0x89, 0x53, 0xe2, 0xdf, 0x9f, 0xe7, 0xf7, 0xde, 0x2f, 0x81, 0x37, 0x06,
	0xe5, 0xb5, 0x44, 0x63, 0xb0, 0xbc, 0x2e, 0x31, 0x57, 0xba, 0x5c, 0x61, 0x66, 0x1d, 0x06, 0x64,
	0x60, 0x50, 0x66, 0x2d, 0x35, 0x7a, 0xbd, 0x27, 0x6b, 0x1f, 0xad, 0x68, 0xf4, 0xae, 0x4b, 0xd8,
	0x2a, 0xa8, 0x7d, 0x7e, 0xf2, 0x3b, 0x82, 0x64, 0xe1, 0x50, 0x2a, 0xef, 0xd1, 0x31, 0x06, 0xfd,
	0x52, 0x18, 0x95, 0x46, 0xe3, 0x68, 0x9a, 0x70, 0x7a, 0x67, 0x2f, 0xe1, 0x50, 0xa2, 0x53, 0x3e,
	0x3d, 0x18, 0x47, 0xd3, 0x67, 0xbc, 0x3d, 0x34, 0xa8, 0xb7, 0x4a, 0xe5, 0x69, 0x8f, 0xa4, 0xed,
	0x81, 0x9d, 0x40, 0x3f, 0xd4, 0x56, 0xa5, 0xfd, 0x71, 0x34, 0x1d, 0xce, 0x59, 0xd6, 0x74, 0xb8,
	0xad, 0xfe, 0xa3, 0xb6, 0x8a, 0x13, 0xcf, 0x4e, 0x60, 0x78, 0xab, 0x5d, 0xa8, 0x44, 0xa1, 0xef,
	0x44, 0xd0, 0x58, 0xa6, 0x87, 0xe3, 0x68, 0x7a, 0xc4, 0x1f, 0xa0, 0xec, 0x23, 0xbc, 0x28, 0x70,
	0xad, 0xa5, 0x28, 0xec, 0x7d, 0x15, 0x9f, 0xc6, 0xd4, 0xc7, 0xbf, 0xc4, 0x24, 0x83, 0xe1, 0xe2,
	0xa6, 0xf6, 0x0d, 0x7a, 0xa1, 0x0c, 0xba, 0x9a, 0xbd, 0x85, 0xc4, 0xeb, 0x3b, 0x75, 0x56, 0x07,
	0xe5, 0x69, 0xa8, 0x3e, 0xdf, 0x01, 0x93, 0x0b, 0xe8, 0x9d, 0x2f, 0xae, 0x1e, 0x1d, 0xba, 0x63,
	0x6c, 0x07, 0xdf, 0x01, 0xed, 0x4a, 0xaa, 0x32, 0xd0, 0xf0, 0xb4, 0x92, 0xaa, 0x0c, 0x93, 0x3f,
	0x11, 0x1c, 0x7d, 0xc3, 0x5c, 0x7d, 0x2d, 0x57, 0xf8, 0x68, 0xd1, 0x21, 0x1c, 0xe8, 0x9c, 0xaa,
	0x25, 0xfc, 0x40, 0xe7, 0xec, 0x33, 0x80, 0x14, 0x56, 0x2c, 0x75, 0xa1, 0x43, 0x4d, 0xb5, 0x06,
	0xf3, 0x57, 0xd9, 0x2e, 0xd5, 0x8c, 0x2b, 0x8f, 0x95, 0x93, 0xca, 0xf3, 0x3d, 0x21, 0xfb, 0x02,
	0x4f, 0xc5, 0xad, 0xd0, 0xc5, 0xbd, 0xb1, 0xff, 0x3f, 0x63, 0x47, 0xca, 0x3e, 0x41, 0x8c, 0x9e,
	0x12, 0x8a, 0x29, 0xa1, 0x94, 0x4c, 0xdf, 0xad, 0x72, 0x22, 0xe8, 0x72, 0x7d, 0x59, 0xfb, 0xa0,
	0x0c, 0xe5, 0xb4, 0xd1, 0xb1, 0x63, 0x88, 0x7d, 0x10, 0xa1, 0xf2, 0xe9, 0x13, 0xba, 0x66, 0x40,
	0x8e, 0x4b, 0x82, 0xf8, 0x86, 0x9a, 0xfc, 0x8a, 0x20, 0xd9, 0x5e, 0xc9, 0x4e, 0x21, 0xd9, 0x86,
	0x42, 0xf3, 0x3f, 0x68, 0x6e, 0xfb, 0x41, 0xf0, 0x9d, 0x8e, 0xcd, 0x21, 0x36, 0x94, 0x19, 0xed,
	0x67, 0x30, 0x1f, 0x75, 0x1c, 0x9d, 0x54, 0xf9, 0x46, 0xc9, 0xde, 0x43, 0x6f, 0x6d, 0xab, 0xcd,
	0xe2, 0x9e, 0xef, 0x1b, 0xce, 0x17, 0x57, 0xbc, 0xe1, 0xce, 0x3e, 0xfc, 0x3c, 0x5e, 0xeb, 0x70,
	0x53, 0x2d, 0x1b, 0x66, 0x66, 0xb4, 0x74, 0xe8, 0x71, 0x15, 0x66, 0x06, 0xe5, 0xcc, 0x59, 0x39,
	0x6b, 0xf5, 0xcb, 0x98, 0x7e, 0x86, 0xd3, 0xbf, 0x01, 0x00, 0x00, 0xff, 0xff, 0x57, 0xb5, 0x9e,
	0x34, 0x6e, 0x03, 0x00, 0x00,
}
