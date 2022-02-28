// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_nodeagent_virtualharddisk.proto

package storage

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	empty "github.com/golang/protobuf/ptypes/empty"
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

type VirtualHardDiskType int32

const (
	VirtualHardDiskType_OS_VIRTUALHARDDISK       VirtualHardDiskType = 0
	VirtualHardDiskType_DATADISK_VIRTUALHARDDISK VirtualHardDiskType = 1
)

var VirtualHardDiskType_name = map[int32]string{
	0: "OS_VIRTUALHARDDISK",
	1: "DATADISK_VIRTUALHARDDISK",
}

var VirtualHardDiskType_value = map[string]int32{
	"OS_VIRTUALHARDDISK":       0,
	"DATADISK_VIRTUALHARDDISK": 1,
}

type HyperVGenerationType int32

const (
	HyperVGenerationType_HyperVGenerationTypeV1 HyperVGenerationType = 1
	HyperVGenerationType_HyperVGenerationTypeV2 HyperVGenerationType = 2
)

var HyperVGenerationType_name = map[int32]string{
	1: "HyperVGenerationTypeV1",
	2: "HyperVGenerationTypeV2",
}

var HyperVGenerationType_value = map[string]int32{
	"HyperVGenerationTypeV1":       1,
	"HyperVGenerationTypeV1":       2,
}


func (x VirtualHardDiskType) String() string {
	return proto.EnumName(VirtualHardDiskType_name, int32(x))
}

func (VirtualHardDiskType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_c1f33a566472b7b7, []int{0}
}

type VirtualHardDiskRequest struct {
	VirtualHardDiskSystems []*VirtualHardDisk `protobuf:"bytes,1,rep,name=VirtualHardDiskSystems,proto3" json:"VirtualHardDiskSystems,omitempty"`
	OperationType          common.Operation   `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}           `json:"-"`
	XXX_unrecognized       []byte             `json:"-"`
	XXX_sizecache          int32              `json:"-"`
}

func (m *VirtualHardDiskRequest) Reset()         { *m = VirtualHardDiskRequest{} }
func (m *VirtualHardDiskRequest) String() string { return proto.CompactTextString(m) }
func (*VirtualHardDiskRequest) ProtoMessage()    {}
func (*VirtualHardDiskRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1f33a566472b7b7, []int{0}
}

func (m *VirtualHardDiskRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualHardDiskRequest.Unmarshal(m, b)
}
func (m *VirtualHardDiskRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualHardDiskRequest.Marshal(b, m, deterministic)
}
func (m *VirtualHardDiskRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualHardDiskRequest.Merge(m, src)
}
func (m *VirtualHardDiskRequest) XXX_Size() int {
	return xxx_messageInfo_VirtualHardDiskRequest.Size(m)
}
func (m *VirtualHardDiskRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualHardDiskRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualHardDiskRequest proto.InternalMessageInfo

func (m *VirtualHardDiskRequest) GetVirtualHardDiskSystems() []*VirtualHardDisk {
	if m != nil {
		return m.VirtualHardDiskSystems
	}
	return nil
}

func (m *VirtualHardDiskRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type VirtualHardDiskResponse struct {
	VirtualHardDiskSystems []*VirtualHardDisk  `protobuf:"bytes,1,rep,name=VirtualHardDiskSystems,proto3" json:"VirtualHardDiskSystems,omitempty"`
	Result                 *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                  string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}            `json:"-"`
	XXX_unrecognized       []byte              `json:"-"`
	XXX_sizecache          int32               `json:"-"`
}

func (m *VirtualHardDiskResponse) Reset()         { *m = VirtualHardDiskResponse{} }
func (m *VirtualHardDiskResponse) String() string { return proto.CompactTextString(m) }
func (*VirtualHardDiskResponse) ProtoMessage()    {}
func (*VirtualHardDiskResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1f33a566472b7b7, []int{1}
}

func (m *VirtualHardDiskResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualHardDiskResponse.Unmarshal(m, b)
}
func (m *VirtualHardDiskResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualHardDiskResponse.Marshal(b, m, deterministic)
}
func (m *VirtualHardDiskResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualHardDiskResponse.Merge(m, src)
}
func (m *VirtualHardDiskResponse) XXX_Size() int {
	return xxx_messageInfo_VirtualHardDiskResponse.Size(m)
}
func (m *VirtualHardDiskResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualHardDiskResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualHardDiskResponse proto.InternalMessageInfo

func (m *VirtualHardDiskResponse) GetVirtualHardDiskSystems() []*VirtualHardDisk {
	if m != nil {
		return m.VirtualHardDiskSystems
	}
	return nil
}

func (m *VirtualHardDiskResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *VirtualHardDiskResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type SFSImageProperties struct {
	CatalogName          string   `protobuf:"bytes,1,opt,name=catalogName,proto3" json:"catalogName,omitempty"`
	Audience             string   `protobuf:"bytes,2,opt,name=audience,proto3" json:"audience,omitempty"`
	Version              string   `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	ReleaseName          string   `protobuf:"bytes,4,opt,name=releaseName,proto3" json:"releaseName,omitempty"`
	Parts                uint32   `protobuf:"varint,5,opt,name=parts,proto3" json:"parts,omitempty"`
	DestinationDir       string   `protobuf:"bytes,6,opt,name=destinationDir,proto3" json:"destinationDir,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SFSImageProperties) Reset()         { *m = SFSImageProperties{} }
func (m *SFSImageProperties) String() string { return proto.CompactTextString(m) }
func (*SFSImageProperties) ProtoMessage()    {}
func (*SFSImageProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1f33a566472b7b7, []int{2}
}

func (m *SFSImageProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SFSImageProperties.Unmarshal(m, b)
}
func (m *SFSImageProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SFSImageProperties.Marshal(b, m, deterministic)
}
func (m *SFSImageProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SFSImageProperties.Merge(m, src)
}
func (m *SFSImageProperties) XXX_Size() int {
	return xxx_messageInfo_SFSImageProperties.Size(m)
}
func (m *SFSImageProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_SFSImageProperties.DiscardUnknown(m)
}

var xxx_messageInfo_SFSImageProperties proto.InternalMessageInfo

func (m *SFSImageProperties) GetCatalogName() string {
	if m != nil {
		return m.CatalogName
	}
	return ""
}

func (m *SFSImageProperties) GetAudience() string {
	if m != nil {
		return m.Audience
	}
	return ""
}

func (m *SFSImageProperties) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *SFSImageProperties) GetReleaseName() string {
	if m != nil {
		return m.ReleaseName
	}
	return ""
}

func (m *SFSImageProperties) GetParts() uint32 {
	if m != nil {
		return m.Parts
	}
	return 0
}

func (m *SFSImageProperties) GetDestinationDir() string {
	if m != nil {
		return m.DestinationDir
	}
	return ""
}

type LocalImageProperties struct {
	Path                 string   `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LocalImageProperties) Reset()         { *m = LocalImageProperties{} }
func (m *LocalImageProperties) String() string { return proto.CompactTextString(m) }
func (*LocalImageProperties) ProtoMessage()    {}
func (*LocalImageProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1f33a566472b7b7, []int{3}
}

func (m *LocalImageProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalImageProperties.Unmarshal(m, b)
}
func (m *LocalImageProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalImageProperties.Marshal(b, m, deterministic)
}
func (m *LocalImageProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalImageProperties.Merge(m, src)
}
func (m *LocalImageProperties) XXX_Size() int {
	return xxx_messageInfo_LocalImageProperties.Size(m)
}
func (m *LocalImageProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalImageProperties.DiscardUnknown(m)
}

var xxx_messageInfo_LocalImageProperties proto.InternalMessageInfo

func (m *LocalImageProperties) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

type CloneImageProperties struct {
	CloneSource          string   `protobuf:"bytes,1,opt,name=cloneSource,proto3" json:"cloneSource,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CloneImageProperties) Reset()         { *m = CloneImageProperties{} }
func (m *CloneImageProperties) String() string { return proto.CompactTextString(m) }
func (*CloneImageProperties) ProtoMessage()    {}
func (*CloneImageProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1f33a566472b7b7, []int{4}
}

func (m *CloneImageProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CloneImageProperties.Unmarshal(m, b)
}
func (m *CloneImageProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CloneImageProperties.Marshal(b, m, deterministic)
}
func (m *CloneImageProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CloneImageProperties.Merge(m, src)
}
func (m *CloneImageProperties) XXX_Size() int {
	return xxx_messageInfo_CloneImageProperties.Size(m)
}
func (m *CloneImageProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_CloneImageProperties.DiscardUnknown(m)
}

var xxx_messageInfo_CloneImageProperties proto.InternalMessageInfo

func (m *CloneImageProperties) GetCloneSource() string {
	if m != nil {
		return m.CloneSource
	}
	return ""
}

type HttpImageProperties struct {
	HttpURL              string   `protobuf:"bytes,1,opt,name=httpURL,proto3" json:"httpURL,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HttpImageProperties) Reset()         { *m = HttpImageProperties{} }
func (m *HttpImageProperties) String() string { return proto.CompactTextString(m) }
func (*HttpImageProperties) ProtoMessage()    {}
func (*HttpImageProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1f33a566472b7b7, []int{5}
}

func (m *HttpImageProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HttpImageProperties.Unmarshal(m, b)
}
func (m *HttpImageProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HttpImageProperties.Marshal(b, m, deterministic)
}
func (m *HttpImageProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HttpImageProperties.Merge(m, src)
}
func (m *HttpImageProperties) XXX_Size() int {
	return xxx_messageInfo_HttpImageProperties.Size(m)
}
func (m *HttpImageProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_HttpImageProperties.DiscardUnknown(m)
}

var xxx_messageInfo_HttpImageProperties proto.InternalMessageInfo

func (m *HttpImageProperties) GetHttpURL() string {
	if m != nil {
		return m.HttpURL
	}
	return ""
}

type VirtualHardDisk struct {
	Name   string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id     string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Source string `protobuf:"bytes,3,opt,name=source,proto3" json:"source,omitempty"`
	Path   string `protobuf:"bytes,4,opt,name=path,proto3" json:"path,omitempty"`
	// Storage container name to hold this vhd
	ContainerName        string              `protobuf:"bytes,5,opt,name=containerName,proto3" json:"containerName,omitempty"`
	Status               *common.Status      `protobuf:"bytes,6,opt,name=status,proto3" json:"status,omitempty"`
	Size                 int64               `protobuf:"varint,7,opt,name=size,proto3" json:"size,omitempty"`
	Dynamic              bool                `protobuf:"varint,8,opt,name=dynamic,proto3" json:"dynamic,omitempty"`
	Blocksizebytes       int32               `protobuf:"varint,9,opt,name=blocksizebytes,proto3" json:"blocksizebytes,omitempty"`
	Logicalsectorbytes   int32               `protobuf:"varint,10,opt,name=logicalsectorbytes,proto3" json:"logicalsectorbytes,omitempty"`
	Physicalsectorbytes  int32               `protobuf:"varint,11,opt,name=physicalsectorbytes,proto3" json:"physicalsectorbytes,omitempty"`
	Controllernumber     int64               `protobuf:"varint,12,opt,name=controllernumber,proto3" json:"controllernumber,omitempty"`
	Controllerlocation   int64               `protobuf:"varint,13,opt,name=controllerlocation,proto3" json:"controllerlocation,omitempty"`
	Disknumber           int64               `protobuf:"varint,14,opt,name=disknumber,proto3" json:"disknumber,omitempty"`
	VirtualmachineName   string              `protobuf:"bytes,15,opt,name=virtualmachineName,proto3" json:"virtualmachineName,omitempty"`
	Scsipath             string              `protobuf:"bytes,16,opt,name=scsipath,proto3" json:"scsipath,omitempty"`
	Virtualharddisktype  VirtualHardDiskType `protobuf:"varint,17,opt,name=virtualharddisktype,proto3,enum=moc.nodeagent.storage.VirtualHardDiskType" json:"virtualharddisktype,omitempty"`
	Entity               *common.Entity      `protobuf:"bytes,18,opt,name=entity,proto3" json:"entity,omitempty"`
	Tags                 *common.Tags        `protobuf:"bytes,19,opt,name=tags,proto3" json:"tags,omitempty"`
	SourceType           common.ImageSource  `protobuf:"varint,20,opt,name=sourceType,proto3,enum=moc.ImageSource" json:"sourceType,omitempty"`
	Hypervgenerationtype HyperVGenerationType `protobuf:"varint,21,opt,name=hypervgenerationtype,proto3,enum=moc.nodeagent.storage.HyperVGenerationType" json:"hypervgenerationtype,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *VirtualHardDisk) Reset()         { *m = VirtualHardDisk{} }
func (m *VirtualHardDisk) String() string { return proto.CompactTextString(m) }
func (*VirtualHardDisk) ProtoMessage()    {}
func (*VirtualHardDisk) Descriptor() ([]byte, []int) {
	return fileDescriptor_c1f33a566472b7b7, []int{6}
}

func (m *VirtualHardDisk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VirtualHardDisk.Unmarshal(m, b)
}
func (m *VirtualHardDisk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VirtualHardDisk.Marshal(b, m, deterministic)
}
func (m *VirtualHardDisk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VirtualHardDisk.Merge(m, src)
}
func (m *VirtualHardDisk) XXX_Size() int {
	return xxx_messageInfo_VirtualHardDisk.Size(m)
}
func (m *VirtualHardDisk) XXX_DiscardUnknown() {
	xxx_messageInfo_VirtualHardDisk.DiscardUnknown(m)
}

var xxx_messageInfo_VirtualHardDisk proto.InternalMessageInfo

func (m *VirtualHardDisk) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *VirtualHardDisk) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *VirtualHardDisk) GetSource() string {
	if m != nil {
		return m.Source
	}
	return ""
}

func (m *VirtualHardDisk) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *VirtualHardDisk) GetContainerName() string {
	if m != nil {
		return m.ContainerName
	}
	return ""
}

func (m *VirtualHardDisk) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *VirtualHardDisk) GetSize() int64 {
	if m != nil {
		return m.Size
	}
	return 0
}

func (m *VirtualHardDisk) GetDynamic() bool {
	if m != nil {
		return m.Dynamic
	}
	return false
}

func (m *VirtualHardDisk) GetBlocksizebytes() int32 {
	if m != nil {
		return m.Blocksizebytes
	}
	return 0
}

func (m *VirtualHardDisk) GetLogicalsectorbytes() int32 {
	if m != nil {
		return m.Logicalsectorbytes
	}
	return 0
}

func (m *VirtualHardDisk) GetPhysicalsectorbytes() int32 {
	if m != nil {
		return m.Physicalsectorbytes
	}
	return 0
}

func (m *VirtualHardDisk) GetControllernumber() int64 {
	if m != nil {
		return m.Controllernumber
	}
	return 0
}

func (m *VirtualHardDisk) GetControllerlocation() int64 {
	if m != nil {
		return m.Controllerlocation
	}
	return 0
}

func (m *VirtualHardDisk) GetDisknumber() int64 {
	if m != nil {
		return m.Disknumber
	}
	return 0
}

func (m *VirtualHardDisk) GetVirtualmachineName() string {
	if m != nil {
		return m.VirtualmachineName
	}
	return ""
}

func (m *VirtualHardDisk) GetScsipath() string {
	if m != nil {
		return m.Scsipath
	}
	return ""
}

func (m *VirtualHardDisk) GetVirtualharddisktype() VirtualHardDiskType {
	if m != nil {
		return m.Virtualharddisktype
	}
	return VirtualHardDiskType_OS_VIRTUALHARDDISK
}

func (m *VirtualHardDisk) GetEntity() *common.Entity {
	if m != nil {
		return m.Entity
	}
	return nil
}

func (m *VirtualHardDisk) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func (m *VirtualHardDisk) GetSourceType() common.ImageSource {
	if m != nil {
		return m.SourceType
	}
	return common.ImageSource_LOCAL_SOURCE
}

func (m *VirtualHardDisk) GetHypervgenerationtype() HyperVGenerationType {
	if m != nil {
		return m.Hypervgenerationtype
	}
	return HyperVGenerationType_HyperVGenerationTypeV2
}

func init() {
	proto.RegisterEnum("moc.nodeagent.storage.VirtualHardDiskType", VirtualHardDiskType_name, VirtualHardDiskType_value)
	proto.RegisterType((*VirtualHardDiskRequest)(nil), "moc.nodeagent.storage.VirtualHardDiskRequest")
	proto.RegisterType((*VirtualHardDiskResponse)(nil), "moc.nodeagent.storage.VirtualHardDiskResponse")
	proto.RegisterType((*SFSImageProperties)(nil), "moc.nodeagent.storage.SFSImageProperties")
	proto.RegisterType((*LocalImageProperties)(nil), "moc.nodeagent.storage.LocalImageProperties")
	proto.RegisterType((*CloneImageProperties)(nil), "moc.nodeagent.storage.CloneImageProperties")
	proto.RegisterType((*HttpImageProperties)(nil), "moc.nodeagent.storage.HttpImageProperties")
	proto.RegisterType((*VirtualHardDisk)(nil), "moc.nodeagent.storage.VirtualHardDisk")
}

func init() {
	proto.RegisterFile("moc_nodeagent_virtualharddisk.proto", fileDescriptor_c1f33a566472b7b7)
}

var fileDescriptor_c1f33a566472b7b7 = []byte{
	// 880 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x55, 0x5d, 0x6f, 0xdb, 0x36,
	0x14, 0xad, 0xf2, 0xe1, 0x24, 0xd7, 0x8b, 0x9b, 0xd2, 0x5e, 0xaa, 0x79, 0x6b, 0x61, 0xb8, 0x43,
	0x61, 0x04, 0x98, 0x1c, 0x78, 0x7b, 0xd8, 0xab, 0x5b, 0x67, 0x48, 0xd0, 0xa0, 0x1d, 0xe8, 0x34,
	0x0f, 0xc3, 0xb0, 0x80, 0xa6, 0x18, 0x99, 0xb0, 0x44, 0x6a, 0x24, 0x95, 0xc1, 0x7b, 0xda, 0x2f,
	0xda, 0x9f, 0xd8, 0xe3, 0xf6, 0xa3, 0x06, 0x92, 0xf2, 0x47, 0x65, 0x0f, 0xc8, 0xcb, 0x9e, 0xac,
	0x7b, 0xcf, 0xb9, 0xc7, 0xe7, 0x5e, 0x91, 0x57, 0xf0, 0x2a, 0x93, 0xf4, 0x4e, 0xc8, 0x98, 0x91,
	0x84, 0x09, 0x73, 0xf7, 0xc0, 0x95, 0x29, 0x48, 0x3a, 0x25, 0x2a, 0x8e, 0xb9, 0x9e, 0x45, 0xb9,
	0x92, 0x46, 0xa2, 0xcf, 0x33, 0x49, 0xa3, 0x25, 0x29, 0xd2, 0x46, 0x2a, 0x92, 0xb0, 0xf6, 0xcb,
	0x44, 0xca, 0x24, 0x65, 0x7d, 0x47, 0x9a, 0x14, 0xf7, 0xfd, 0xdf, 0x14, 0xc9, 0x73, 0xa6, 0xb4,
	0x2f, 0x6b, 0x3f, 0xb7, 0xda, 0x54, 0x66, 0x99, 0x14, 0xe5, 0x4f, 0x09, 0xbc, 0x58, 0x03, 0x84,
	0x34, 0xfc, 0x9e, 0x53, 0x62, 0xf8, 0x12, 0xfe, 0xb2, 0xaa, 0xcb, 0xb2, 0xdc, 0xcc, 0x3d, 0xd8,
	0xfd, 0x33, 0x80, 0xd3, 0x5b, 0xef, 0xf2, 0x92, 0xa8, 0x78, 0xc4, 0xf5, 0x0c, 0xb3, 0x5f, 0x0b,
	0xa6, 0x0d, 0xfa, 0x65, 0x03, 0x19, 0xcf, 0xb5, 0x61, 0x99, 0x0e, 0x83, 0xce, 0x6e, 0xaf, 0x3e,
	0x78, 0x1d, 0x6d, 0xed, 0x23, 0xaa, 0xca, 0xfd, 0x87, 0x0a, 0xfa, 0x0e, 0x8e, 0x3f, 0xe4, 0x4c,
	0x39, 0xab, 0x37, 0xf3, 0x9c, 0x85, 0x3b, 0x9d, 0xa0, 0xd7, 0x18, 0x34, 0x9c, 0xec, 0x12, 0xc1,
	0x9f, 0x92, 0xba, 0x7f, 0x05, 0xf0, 0x7c, 0xc3, 0xb0, 0xce, 0xa5, 0xd0, 0xec, 0x7f, 0x77, 0x3c,
	0x80, 0x1a, 0x66, 0xba, 0x48, 0x8d, 0xb3, 0x5a, 0x1f, 0xb4, 0x23, 0x3f, 0xda, 0x68, 0x31, 0xda,
	0xe8, 0x8d, 0x94, 0xe9, 0x2d, 0x49, 0x0b, 0x86, 0x4b, 0x26, 0x6a, 0xc1, 0xfe, 0x85, 0x52, 0x52,
	0x85, 0xbb, 0x9d, 0xa0, 0x77, 0x84, 0x7d, 0xd0, 0xfd, 0x27, 0x00, 0x34, 0xfe, 0x61, 0x7c, 0x95,
	0x91, 0x84, 0xfd, 0xa8, 0x64, 0xce, 0x94, 0xe1, 0x4c, 0xa3, 0x0e, 0xd4, 0x29, 0x31, 0x24, 0x95,
	0xc9, 0x7b, 0x92, 0xb1, 0x30, 0x70, 0x25, 0xeb, 0x29, 0xd4, 0x86, 0x43, 0x52, 0xc4, 0x9c, 0x09,
	0xea, 0xe7, 0x75, 0x84, 0x97, 0x31, 0x0a, 0xe1, 0xe0, 0x81, 0x29, 0xcd, 0xa5, 0x28, 0xff, 0x6c,
	0x11, 0x5a, 0x5d, 0xc5, 0x52, 0x46, 0x34, 0x73, 0xba, 0x7b, 0x5e, 0x77, 0x2d, 0x65, 0x6d, 0xe6,
	0x44, 0x19, 0x1d, 0xee, 0x77, 0x82, 0xde, 0x31, 0xf6, 0x01, 0x7a, 0x0d, 0x8d, 0x98, 0x69, 0xc3,
	0x85, 0x9b, 0xff, 0x88, 0xab, 0xb0, 0xe6, 0x4a, 0x2b, 0xd9, 0xee, 0x19, 0xb4, 0xae, 0x25, 0x25,
	0x69, 0xb5, 0x1f, 0x04, 0x7b, 0x39, 0x31, 0xd3, 0xb2, 0x11, 0xf7, 0xdc, 0xfd, 0x1e, 0x5a, 0x6f,
	0x53, 0x29, 0xd8, 0xb6, 0xde, 0x6d, 0x7e, 0x2c, 0x0b, 0x45, 0x57, 0xbd, 0xaf, 0x52, 0xdd, 0x3e,
	0x34, 0x2f, 0x8d, 0xc9, 0xab, 0x85, 0x21, 0x1c, 0x4c, 0x8d, 0xc9, 0x3f, 0xe2, 0xeb, 0xb2, 0x68,
	0x11, 0x76, 0xff, 0xa8, 0xc1, 0xd3, 0xca, 0xab, 0xb4, 0x96, 0xc4, 0x6a, 0xb6, 0xee, 0x19, 0x35,
	0x60, 0x87, 0xc7, 0xe5, 0x38, 0x77, 0x78, 0x8c, 0x4e, 0xa1, 0xa6, 0xbd, 0x0b, 0x3f, 0xc7, 0x32,
	0x5a, 0xb6, 0xb3, 0xb7, 0x6a, 0x07, 0x7d, 0x0d, 0xc7, 0x54, 0x0a, 0x43, 0xb8, 0x60, 0xca, 0x0d,
	0x77, 0xdf, 0x81, 0x9f, 0x26, 0xd1, 0x2b, 0xa8, 0x69, 0x43, 0x4c, 0xa1, 0xdd, 0x00, 0xeb, 0x83,
	0xba, 0x3b, 0x89, 0x63, 0x97, 0xc2, 0x25, 0x64, 0xe5, 0x35, 0xff, 0x9d, 0x85, 0x07, 0x9d, 0xa0,
	0xb7, 0x8b, 0xdd, 0xb3, 0x6d, 0x2e, 0x9e, 0x0b, 0x92, 0x71, 0x1a, 0x1e, 0x76, 0x82, 0xde, 0x21,
	0x5e, 0x84, 0xf6, 0xdd, 0x4c, 0x52, 0x49, 0x67, 0x96, 0x36, 0x99, 0x1b, 0xa6, 0xc3, 0xa3, 0x4e,
	0xd0, 0xdb, 0xc7, 0x95, 0x2c, 0x8a, 0x00, 0xa5, 0x32, 0xe1, 0x94, 0xa4, 0x9a, 0x51, 0x23, 0x95,
	0xe7, 0x82, 0xe3, 0x6e, 0x41, 0xd0, 0x39, 0x34, 0xf3, 0xe9, 0x5c, 0x57, 0x0b, 0xea, 0xae, 0x60,
	0x1b, 0x84, 0xce, 0xe0, 0xc4, 0x76, 0xab, 0x64, 0x9a, 0x32, 0x25, 0x8a, 0x6c, 0xc2, 0x54, 0xf8,
	0x99, 0xeb, 0x61, 0x23, 0x6f, 0xdd, 0xac, 0x72, 0xa9, 0xf4, 0x8b, 0x2a, 0x3c, 0x76, 0xec, 0x2d,
	0x08, 0x7a, 0x09, 0x60, 0x37, 0x67, 0xa9, 0xda, 0x70, 0xbc, 0xb5, 0x8c, 0xd5, 0x2b, 0x97, 0x6c,
	0x46, 0xe8, 0x94, 0x0b, 0x7f, 0xc0, 0x9f, 0xba, 0x77, 0xb0, 0x05, 0xb1, 0xf7, 0x47, 0x53, 0xcd,
	0xdd, 0x6b, 0x3c, 0xf1, 0xf7, 0x67, 0x11, 0xa3, 0x9f, 0xa1, 0x59, 0x59, 0xd8, 0xc6, 0xae, 0xa5,
	0x67, 0x6e, 0x2d, 0x9d, 0x3d, 0x6e, 0x77, 0xd8, 0x1d, 0x85, 0xb7, 0xc9, 0xd8, 0x23, 0xc0, 0x84,
	0xe1, 0x66, 0x1e, 0xa2, 0xb5, 0x23, 0x70, 0xe1, 0x52, 0xb8, 0x84, 0xd0, 0x0b, 0xd8, 0x33, 0x24,
	0xd1, 0x61, 0xd3, 0x51, 0x8e, 0x1c, 0xe5, 0x86, 0x24, 0x1a, 0xbb, 0x34, 0x3a, 0x07, 0xf0, 0x47,
	0xd1, 0xed, 0xcb, 0x96, 0x33, 0x76, 0xe2, 0x48, 0xee, 0x52, 0xf8, 0x7b, 0x82, 0xd7, 0x38, 0x67,
	0xef, 0xa0, 0xb9, 0xc5, 0x21, 0x3a, 0x05, 0xf4, 0x61, 0x7c, 0x77, 0x7b, 0x85, 0x6f, 0x3e, 0x0e,
	0xaf, 0x2f, 0x87, 0x78, 0x34, 0xba, 0x1a, 0xbf, 0x3b, 0x79, 0x82, 0xbe, 0x82, 0x70, 0x34, 0xbc,
	0x19, 0xda, 0x68, 0x03, 0x0d, 0x06, 0x7f, 0x07, 0xd0, 0xaa, 0xa8, 0x0d, 0xed, 0x30, 0x10, 0x87,
	0xda, 0x95, 0x78, 0x90, 0x33, 0x86, 0xbe, 0x79, 0xe4, 0x8a, 0xf5, 0xdf, 0x98, 0x76, 0xf4, 0x58,
	0xba, 0xdf, 0xf0, 0xdd, 0x27, 0xe8, 0x12, 0x9e, 0xbd, 0x9d, 0x32, 0x3a, 0x7b, 0xbf, 0xf6, 0xa1,
	0x43, 0xa7, 0x1b, 0x8b, 0xf8, 0xc2, 0x7e, 0xe3, 0xda, 0x5f, 0x38, 0xf9, 0x75, 0xea, 0x4a, 0xe9,
	0xcd, 0xf9, 0x4f, 0x51, 0xc2, 0xcd, 0xb4, 0x98, 0x44, 0x54, 0x66, 0xfd, 0x8c, 0x53, 0x25, 0xb5,
	0xbc, 0x37, 0xfd, 0x4c, 0xd2, 0xbe, 0xca, 0x69, 0x7f, 0xe9, 0xaa, 0x5f, 0xba, 0x9a, 0xd4, 0x9c,
	0xfc, 0xb7, 0xff, 0x06, 0x00, 0x00, 0xff, 0xff, 0xc1, 0xbc, 0x6a, 0xd8, 0xe6, 0x07, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// VirtualHardDiskAgentClient is the client API for VirtualHardDiskAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type VirtualHardDiskAgentClient interface {
	Invoke(ctx context.Context, in *VirtualHardDiskRequest, opts ...grpc.CallOption) (*VirtualHardDiskResponse, error)
	CheckNotification(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*common.NotificationResponse, error)
}

type virtualHardDiskAgentClient struct {
	cc *grpc.ClientConn
}

func NewVirtualHardDiskAgentClient(cc *grpc.ClientConn) VirtualHardDiskAgentClient {
	return &virtualHardDiskAgentClient{cc}
}

func (c *virtualHardDiskAgentClient) Invoke(ctx context.Context, in *VirtualHardDiskRequest, opts ...grpc.CallOption) (*VirtualHardDiskResponse, error) {
	out := new(VirtualHardDiskResponse)
	err := c.cc.Invoke(ctx, "/moc.nodeagent.storage.VirtualHardDiskAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *virtualHardDiskAgentClient) CheckNotification(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*common.NotificationResponse, error) {
	out := new(common.NotificationResponse)
	err := c.cc.Invoke(ctx, "/moc.nodeagent.storage.VirtualHardDiskAgent/CheckNotification", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VirtualHardDiskAgentServer is the server API for VirtualHardDiskAgent service.
type VirtualHardDiskAgentServer interface {
	Invoke(context.Context, *VirtualHardDiskRequest) (*VirtualHardDiskResponse, error)
	CheckNotification(context.Context, *empty.Empty) (*common.NotificationResponse, error)
}

// UnimplementedVirtualHardDiskAgentServer can be embedded to have forward compatible implementations.
type UnimplementedVirtualHardDiskAgentServer struct {
}

func (*UnimplementedVirtualHardDiskAgentServer) Invoke(ctx context.Context, req *VirtualHardDiskRequest) (*VirtualHardDiskResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}
func (*UnimplementedVirtualHardDiskAgentServer) CheckNotification(ctx context.Context, req *empty.Empty) (*common.NotificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckNotification not implemented")
}

func RegisterVirtualHardDiskAgentServer(s *grpc.Server, srv VirtualHardDiskAgentServer) {
	s.RegisterService(&_VirtualHardDiskAgent_serviceDesc, srv)
}

func _VirtualHardDiskAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VirtualHardDiskRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VirtualHardDiskAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.nodeagent.storage.VirtualHardDiskAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VirtualHardDiskAgentServer).Invoke(ctx, req.(*VirtualHardDiskRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _VirtualHardDiskAgent_CheckNotification_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VirtualHardDiskAgentServer).CheckNotification(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.nodeagent.storage.VirtualHardDiskAgent/CheckNotification",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VirtualHardDiskAgentServer).CheckNotification(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

var _VirtualHardDiskAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.nodeagent.storage.VirtualHardDiskAgent",
	HandlerType: (*VirtualHardDiskAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _VirtualHardDiskAgent_Invoke_Handler,
		},
		{
			MethodName: "CheckNotification",
			Handler:    _VirtualHardDiskAgent_CheckNotification_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_nodeagent_virtualharddisk.proto",
}
