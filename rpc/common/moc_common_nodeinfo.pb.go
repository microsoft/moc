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

type OsRegistrationState int32

const (
	OsRegistrationState_notRegistered OsRegistrationState = 0
	OsRegistrationState_registered    OsRegistrationState = 1
)

var OsRegistrationState_name = map[int32]string{
	0: "notRegistered",
	1: "registered",
}

var OsRegistrationState_value = map[string]int32{
	"notRegistered": 0,
	"registered":    1,
}

func (x OsRegistrationState) String() string {
	return proto.EnumName(OsRegistrationState_name, int32(x))
}

func (OsRegistrationState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{0}
}

type OsRegistrationStatus struct {
	Status               OsRegistrationState `protobuf:"varint,1,opt,name=status,proto3,enum=moc.common.OsRegistrationState" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *OsRegistrationStatus) Reset()         { *m = OsRegistrationStatus{} }
func (m *OsRegistrationStatus) String() string { return proto.CompactTextString(m) }
func (*OsRegistrationStatus) ProtoMessage()    {}
func (*OsRegistrationStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{0}
}

func (m *OsRegistrationStatus) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OsRegistrationStatus.Unmarshal(m, b)
}
func (m *OsRegistrationStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OsRegistrationStatus.Marshal(b, m, deterministic)
}
func (m *OsRegistrationStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OsRegistrationStatus.Merge(m, src)
}
func (m *OsRegistrationStatus) XXX_Size() int {
	return xxx_messageInfo_OsRegistrationStatus.Size(m)
}
func (m *OsRegistrationStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_OsRegistrationStatus.DiscardUnknown(m)
}

var xxx_messageInfo_OsRegistrationStatus proto.InternalMessageInfo

func (m *OsRegistrationStatus) GetStatus() OsRegistrationState {
	if m != nil {
		return m.Status
	}
	return OsRegistrationState_notRegistered
}

type Processor struct {
	Name                 string        `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Cores                uint32        `protobuf:"varint,2,opt,name=cores,proto3" json:"cores,omitempty"`
	Speed                string        `protobuf:"bytes,3,opt,name=speed,proto3" json:"speed,omitempty"`
	Type                 ProcessorType `protobuf:"varint,4,opt,name=type,proto3,enum=moc.ProcessorType" json:"type,omitempty"`
	Virtualization       bool          `protobuf:"varint,5,opt,name=virtualization,proto3" json:"virtualization,omitempty"`
	Logicalprocessors    uint32        `protobuf:"varint,6,opt,name=logicalprocessors,proto3" json:"logicalprocessors,omitempty"`
	Hypervisorpresent    bool          `protobuf:"varint,7,opt,name=hypervisorpresent,proto3" json:"hypervisorpresent,omitempty"`
	Manufacturer         string        `protobuf:"bytes,8,opt,name=manufacturer,proto3" json:"manufacturer,omitempty"`
	Architecture         Architecture  `protobuf:"varint,9,opt,name=architecture,proto3,enum=moc.Architecture" json:"architecture,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *Processor) Reset()         { *m = Processor{} }
func (m *Processor) String() string { return proto.CompactTextString(m) }
func (*Processor) ProtoMessage()    {}
func (*Processor) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{1}
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

func (m *Processor) GetHypervisorpresent() bool {
	if m != nil {
		return m.Hypervisorpresent
	}
	return false
}

func (m *Processor) GetManufacturer() string {
	if m != nil {
		return m.Manufacturer
	}
	return ""
}

func (m *Processor) GetArchitecture() Architecture {
	if m != nil {
		return m.Architecture
	}
	return Architecture_x86
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
	return fileDescriptor_7c83f03f7e6831a3, []int{2}
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
	return fileDescriptor_7c83f03f7e6831a3, []int{3}
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

type OperatingSystem struct {
	Operatingsystemsku   uint64                `protobuf:"varint,1,opt,name=operatingsystemsku,proto3" json:"operatingsystemsku,omitempty"`
	Ostype               OperatingSystemType   `protobuf:"varint,2,opt,name=ostype,proto3,enum=moc.OperatingSystemType" json:"ostype,omitempty"`
	OsRegistrationStatus *OsRegistrationStatus `protobuf:"bytes,3,opt,name=osRegistrationStatus,proto3" json:"osRegistrationStatus,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *OperatingSystem) Reset()         { *m = OperatingSystem{} }
func (m *OperatingSystem) String() string { return proto.CompactTextString(m) }
func (*OperatingSystem) ProtoMessage()    {}
func (*OperatingSystem) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{4}
}

func (m *OperatingSystem) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OperatingSystem.Unmarshal(m, b)
}
func (m *OperatingSystem) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OperatingSystem.Marshal(b, m, deterministic)
}
func (m *OperatingSystem) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OperatingSystem.Merge(m, src)
}
func (m *OperatingSystem) XXX_Size() int {
	return xxx_messageInfo_OperatingSystem.Size(m)
}
func (m *OperatingSystem) XXX_DiscardUnknown() {
	xxx_messageInfo_OperatingSystem.DiscardUnknown(m)
}

var xxx_messageInfo_OperatingSystem proto.InternalMessageInfo

func (m *OperatingSystem) GetOperatingsystemsku() uint64 {
	if m != nil {
		return m.Operatingsystemsku
	}
	return 0
}

func (m *OperatingSystem) GetOstype() OperatingSystemType {
	if m != nil {
		return m.Ostype
	}
	return OperatingSystemType_WINDOWS
}

func (m *OperatingSystem) GetOsRegistrationStatus() *OsRegistrationStatus {
	if m != nil {
		return m.OsRegistrationStatus
	}
	return nil
}

type NodeInfo struct {
	Name                 string              `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string              `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Capability           *Resources          `protobuf:"bytes,3,opt,name=capability,proto3" json:"capability,omitempty"`
	Availability         *Resources          `protobuf:"bytes,4,opt,name=availability,proto3" json:"availability,omitempty"`
	Ostype               OperatingSystemType `protobuf:"varint,6,opt,name=ostype,proto3,enum=moc.OperatingSystemType" json:"ostype,omitempty"`
	Status               *Status             `protobuf:"bytes,7,opt,name=status,proto3" json:"status,omitempty"`
	Uptime               int64               `protobuf:"varint,8,opt,name=uptime,proto3" json:"uptime,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *NodeInfo) Reset()         { *m = NodeInfo{} }
func (m *NodeInfo) String() string { return proto.CompactTextString(m) }
func (*NodeInfo) ProtoMessage()    {}
func (*NodeInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{5}
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

func (m *NodeInfo) GetUptime() int64 {
	if m != nil {
		return m.Uptime
	}
	return 0
}

type Resources struct {
	Processor            *Processor       `protobuf:"bytes,1,opt,name=processor,proto3" json:"processor,omitempty"`
	Memory               *PhysicalMemory  `protobuf:"bytes,2,opt,name=memory,proto3" json:"memory,omitempty"`
	Gpu                  *GPU             `protobuf:"bytes,3,opt,name=gpu,proto3" json:"gpu,omitempty"`
	OsInfo               *OperatingSystem `protobuf:"bytes,4,opt,name=osInfo,proto3" json:"osInfo,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *Resources) Reset()         { *m = Resources{} }
func (m *Resources) String() string { return proto.CompactTextString(m) }
func (*Resources) ProtoMessage()    {}
func (*Resources) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c83f03f7e6831a3, []int{6}
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

func (m *Resources) GetOsInfo() *OperatingSystem {
	if m != nil {
		return m.OsInfo
	}
	return nil
}

func init() {
	proto.RegisterEnum("moc.common.OsRegistrationState", OsRegistrationState_name, OsRegistrationState_value)
	proto.RegisterType((*OsRegistrationStatus)(nil), "moc.common.OsRegistrationStatus")
	proto.RegisterType((*Processor)(nil), "moc.common.Processor")
	proto.RegisterType((*PhysicalMemory)(nil), "moc.common.PhysicalMemory")
	proto.RegisterType((*GPU)(nil), "moc.common.GPU")
	proto.RegisterType((*OperatingSystem)(nil), "moc.common.OperatingSystem")
	proto.RegisterType((*NodeInfo)(nil), "moc.common.NodeInfo")
	proto.RegisterType((*Resources)(nil), "moc.common.Resources")
}

func init() { proto.RegisterFile("moc_common_nodeinfo.proto", fileDescriptor_7c83f03f7e6831a3) }

var fileDescriptor_7c83f03f7e6831a3 = []byte{
	// 650 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x54, 0x4d, 0x6f, 0xd3, 0x40,
	0x10, 0xc5, 0x49, 0xea, 0xd6, 0xd3, 0x36, 0xa5, 0x4b, 0x01, 0x53, 0x10, 0x04, 0x57, 0x54, 0x15,
	0x42, 0x09, 0x4a, 0x55, 0x01, 0x47, 0x7a, 0xa9, 0x38, 0x94, 0x46, 0xdb, 0xf6, 0xc2, 0xa5, 0x72,
	0x9d, 0x49, 0xb2, 0x22, 0xf6, 0x5a, 0xfb, 0x51, 0xc9, 0xfd, 0x13, 0xfc, 0x2e, 0x24, 0x4e, 0xfc,
	0x22, 0xe4, 0xb1, 0x9b, 0xd8, 0x4d, 0x54, 0x71, 0x4a, 0x76, 0xde, 0x9b, 0x9d, 0xb7, 0xef, 0xed,
	0x1a, 0x5e, 0xc4, 0x32, 0xba, 0x8a, 0x64, 0x1c, 0xcb, 0xe4, 0x2a, 0x91, 0x43, 0x14, 0xc9, 0x48,
	0x76, 0x53, 0x25, 0x8d, 0x64, 0x10, 0xcb, 0xa8, 0x5b, 0x40, 0xbb, 0xcf, 0x2b, 0xb4, 0xe2, 0xa7,
	0x20, 0xed, 0xbe, 0xae, 0x03, 0xa9, 0x35, 0x58, 0xc5, 0x83, 0x33, 0xd8, 0x39, 0xd3, 0x1c, 0xc7,
	0x42, 0x1b, 0x15, 0x1a, 0x21, 0x93, 0x73, 0x13, 0x1a, 0xab, 0xd9, 0x27, 0x70, 0x35, 0xfd, 0xf3,
	0x9d, 0x8e, 0x73, 0xd0, 0xee, 0xbf, 0xe9, 0xce, 0xa7, 0x75, 0x17, 0x3b, 0x90, 0x97, 0xf4, 0xe0,
	0x6f, 0x03, 0xbc, 0x81, 0x92, 0x11, 0x6a, 0x2d, 0x15, 0x63, 0xd0, 0x4a, 0xc2, 0x18, 0x69, 0x13,
	0x8f, 0xd3, 0x7f, 0xb6, 0x03, 0x2b, 0x91, 0x54, 0xa8, 0xfd, 0x46, 0xc7, 0x39, 0xd8, 0xe4, 0xc5,
	0x22, 0xaf, 0xea, 0x14, 0x71, 0xe8, 0x37, 0x89, 0x5a, 0x2c, 0xd8, 0x3e, 0xb4, 0x4c, 0x96, 0xa2,
	0xdf, 0x22, 0x11, 0x8c, 0x44, 0xcc, 0x76, 0xbf, 0xc8, 0x52, 0xe4, 0x84, 0xb3, 0x7d, 0x68, 0xdf,
	0x08, 0x65, 0x6c, 0x38, 0x15, 0xb7, 0x24, 0xca, 0x5f, 0xe9, 0x38, 0x07, 0x6b, 0xfc, 0x5e, 0x95,
	0x7d, 0x80, 0xed, 0xa9, 0x1c, 0x8b, 0x28, 0x9c, 0xa6, 0x77, 0xbb, 0x68, 0xdf, 0x25, 0x1d, 0x8b,
	0x40, 0xce, 0x9e, 0x64, 0x29, 0xaa, 0x1b, 0xa1, 0xa5, 0x4a, 0x15, 0x6a, 0x4c, 0x8c, 0xbf, 0x4a,
	0x1b, 0x2f, 0x02, 0x2c, 0x80, 0x8d, 0x38, 0x4c, 0xec, 0x28, 0x8c, 0x8c, 0x55, 0xa8, 0xfc, 0x35,
	0x3a, 0x48, 0xad, 0xc6, 0x8e, 0x60, 0x23, 0x54, 0xd1, 0x44, 0x18, 0xa4, 0x82, 0xef, 0xd1, 0xb9,
	0xb6, 0xe9, 0x5c, 0x5f, 0x2b, 0x00, 0xaf, 0xd1, 0x82, 0x2e, 0xb4, 0x07, 0x93, 0x4c, 0xe7, 0xf2,
	0x4e, 0x31, 0x96, 0x2a, 0x63, 0xaf, 0xc0, 0xd3, 0xe2, 0x16, 0x8f, 0x33, 0x83, 0x45, 0x44, 0x2d,
	0x3e, 0x2f, 0x04, 0xa7, 0xd0, 0x3c, 0x19, 0x5c, 0x2e, 0x75, 0xbf, 0xd6, 0x58, 0x24, 0x30, 0x2f,
	0x14, 0xd9, 0xd8, 0xc4, 0x50, 0x0a, 0x94, 0x8d, 0x4d, 0x4c, 0xf0, 0xdb, 0x81, 0xad, 0xb3, 0x14,
	0xf3, 0xb8, 0x93, 0xf1, 0x79, 0xa6, 0x0d, 0xc6, 0xac, 0x0b, 0x4c, 0xde, 0x95, 0x34, 0x95, 0xf4,
	0x4f, 0x5b, 0x2a, 0x59, 0x82, 0xb0, 0x8f, 0xe0, 0x4a, 0x4d, 0x59, 0x36, 0xe8, 0xcc, 0x3e, 0x9d,
	0xf9, 0xde, 0xae, 0x94, 0x68, 0xc9, 0x63, 0x17, 0xb0, 0x23, 0x97, 0x5c, 0x4d, 0x92, 0xb6, 0xde,
	0xef, 0x3c, 0x7c, 0x21, 0xad, 0xe6, 0x4b, 0xbb, 0x83, 0x5f, 0x0d, 0x58, 0xfb, 0x2e, 0x87, 0xf8,
	0x2d, 0x19, 0xc9, 0xa5, 0x06, 0xb5, 0xa1, 0x21, 0x86, 0x24, 0xd2, 0xe3, 0x0d, 0x31, 0x64, 0x47,
	0x00, 0x51, 0x98, 0x86, 0xd7, 0x62, 0x2a, 0x4c, 0x56, 0x0e, 0x7f, 0x5a, 0x1d, 0xce, 0x51, 0x4b,
	0xab, 0x22, 0xd4, 0xbc, 0x42, 0x64, 0x5f, 0x60, 0x23, 0xbc, 0x09, 0xc5, 0xf4, 0xae, 0xb1, 0xf5,
	0x50, 0x63, 0x8d, 0x5a, 0xb1, 0xca, 0xfd, 0x4f, 0xab, 0xf6, 0x66, 0xaf, 0x75, 0x95, 0xc6, 0xac,
	0x53, 0x47, 0xe9, 0x43, 0x09, 0xb1, 0x67, 0xe0, 0xda, 0xd4, 0x88, 0x18, 0xe9, 0x66, 0x36, 0x79,
	0xb9, 0x0a, 0xfe, 0x38, 0xe0, 0xcd, 0xa4, 0xb0, 0x43, 0xf0, 0x66, 0x2f, 0x80, 0x7c, 0xb9, 0x27,
	0x7a, 0xf6, 0xfa, 0xf8, 0x9c, 0xc7, 0xfa, 0xe0, 0xc6, 0x74, 0x2f, 0xc9, 0xb7, 0xf5, 0xfe, 0x6e,
	0xad, 0xa3, 0x76, 0x73, 0x79, 0xc9, 0x64, 0x6f, 0xa1, 0x39, 0x4e, 0x6d, 0x69, 0xe8, 0x56, 0xb5,
	0xe1, 0x64, 0x70, 0xc9, 0x73, 0x8c, 0x1d, 0xe6, 0x46, 0xe4, 0x41, 0x95, 0xee, 0xbd, 0xac, 0x65,
	0x5e, 0xf7, 0x83, 0x97, 0xd4, 0xf7, 0x9f, 0xe1, 0xc9, 0x92, 0xef, 0x13, 0xdb, 0x86, 0xcd, 0x44,
	0x9a, 0xa2, 0x8e, 0x0a, 0x87, 0x8f, 0x1f, 0xb1, 0x36, 0x80, 0x9a, 0xaf, 0x9d, 0xe3, 0x77, 0x3f,
	0xf6, 0xc6, 0xc2, 0x4c, 0xec, 0x75, 0x3e, 0xa2, 0x17, 0x8b, 0x48, 0x49, 0x2d, 0x47, 0xa6, 0x17,
	0xcb, 0xa8, 0xa7, 0xd2, 0xa8, 0x57, 0x0c, 0xbe, 0x76, 0xe9, 0xcb, 0x79, 0xf8, 0x2f, 0x00, 0x00,
	0xff, 0xff, 0xa9, 0xfa, 0xd6, 0x39, 0x9b, 0x05, 0x00, 0x00,
}
