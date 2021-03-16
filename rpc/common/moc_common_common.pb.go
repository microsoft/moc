// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_common_common.proto

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

type Operation int32

const (
	Operation_GET    Operation = 0
	Operation_POST   Operation = 1
	Operation_DELETE Operation = 2
	Operation_UPDATE Operation = 3
)

var Operation_name = map[int32]string{
	0: "GET",
	1: "POST",
	2: "DELETE",
	3: "UPDATE",
}

var Operation_value = map[string]int32{
	"GET":    0,
	"POST":   1,
	"DELETE": 2,
	"UPDATE": 3,
}

func (x Operation) String() string {
	return proto.EnumName(Operation_name, int32(x))
}

func (Operation) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{0}
}

type ProvisionState int32

const (
	ProvisionState_UNKNOWN            ProvisionState = 0
	ProvisionState_CREATING           ProvisionState = 1
	ProvisionState_CREATED            ProvisionState = 2
	ProvisionState_CREATE_FAILED      ProvisionState = 3
	ProvisionState_DELETING           ProvisionState = 4
	ProvisionState_DELETE_FAILED      ProvisionState = 5
	ProvisionState_DELETED            ProvisionState = 6
	ProvisionState_UPDATING           ProvisionState = 7
	ProvisionState_UPDATE_FAILED      ProvisionState = 8
	ProvisionState_UPDATED            ProvisionState = 9
	ProvisionState_PROVISIONING       ProvisionState = 10
	ProvisionState_PROVISIONED        ProvisionState = 11
	ProvisionState_PROVISION_FAILED   ProvisionState = 12
	ProvisionState_DEPROVISIONING     ProvisionState = 13
	ProvisionState_DEPROVISIONED      ProvisionState = 14
	ProvisionState_DEPROVISION_FAILED ProvisionState = 15
)

var ProvisionState_name = map[int32]string{
	0:  "UNKNOWN",
	1:  "CREATING",
	2:  "CREATED",
	3:  "CREATE_FAILED",
	4:  "DELETING",
	5:  "DELETE_FAILED",
	6:  "DELETED",
	7:  "UPDATING",
	8:  "UPDATE_FAILED",
	9:  "UPDATED",
	10: "PROVISIONING",
	11: "PROVISIONED",
	12: "PROVISION_FAILED",
	13: "DEPROVISIONING",
	14: "DEPROVISIONED",
	15: "DEPROVISION_FAILED",
}

var ProvisionState_value = map[string]int32{
	"UNKNOWN":            0,
	"CREATING":           1,
	"CREATED":            2,
	"CREATE_FAILED":      3,
	"DELETING":           4,
	"DELETE_FAILED":      5,
	"DELETED":            6,
	"UPDATING":           7,
	"UPDATE_FAILED":      8,
	"UPDATED":            9,
	"PROVISIONING":       10,
	"PROVISIONED":        11,
	"PROVISION_FAILED":   12,
	"DEPROVISIONING":     13,
	"DEPROVISIONED":      14,
	"DEPROVISION_FAILED": 15,
}

func (x ProvisionState) String() string {
	return proto.EnumName(ProvisionState_name, int32(x))
}

func (ProvisionState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{1}
}

type HighAvailabilityState int32

const (
	HighAvailabilityState_UNKNOWN_HA_STATE HighAvailabilityState = 0
	HighAvailabilityState_STABLE           HighAvailabilityState = 1
	HighAvailabilityState_PENDING          HighAvailabilityState = 2
)

var HighAvailabilityState_name = map[int32]string{
	0: "UNKNOWN_HA_STATE",
	1: "STABLE",
	2: "PENDING",
}

var HighAvailabilityState_value = map[string]int32{
	"UNKNOWN_HA_STATE": 0,
	"STABLE":           1,
	"PENDING":          2,
}

func (x HighAvailabilityState) String() string {
	return proto.EnumName(HighAvailabilityState_name, int32(x))
}

func (HighAvailabilityState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{2}
}

type HealthState int32

const (
	HealthState_NOTKNOWN HealthState = 0
	HealthState_OK       HealthState = 1
	HealthState_WARNING  HealthState = 2
	HealthState_CRITICAL HealthState = 3
	// The entity went missing from the platform
	HealthState_MISSING  HealthState = 4
	HealthState_DEGRADED HealthState = 5
	// The entity went missing from the agent
	HealthState_NOTFOUND HealthState = 6
)

var HealthState_name = map[int32]string{
	0: "NOTKNOWN",
	1: "OK",
	2: "WARNING",
	3: "CRITICAL",
	4: "MISSING",
	5: "DEGRADED",
	6: "NOTFOUND",
}

var HealthState_value = map[string]int32{
	"NOTKNOWN": 0,
	"OK":       1,
	"WARNING":  2,
	"CRITICAL": 3,
	"MISSING":  4,
	"DEGRADED": 5,
	"NOTFOUND": 6,
}

func (x HealthState) String() string {
	return proto.EnumName(HealthState_name, int32(x))
}

func (HealthState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{3}
}

type ClientType int32

const (
	ClientType_CONTROLPLANE   ClientType = 0
	ClientType_EXTERNALCLIENT ClientType = 1
	ClientType_NODE           ClientType = 2
	ClientType_ADMIN          ClientType = 3
)

var ClientType_name = map[int32]string{
	0: "CONTROLPLANE",
	1: "EXTERNALCLIENT",
	2: "NODE",
	3: "ADMIN",
}

var ClientType_value = map[string]int32{
	"CONTROLPLANE":   0,
	"EXTERNALCLIENT": 1,
	"NODE":           2,
	"ADMIN":          3,
}

func (x ClientType) String() string {
	return proto.EnumName(ClientType_name, int32(x))
}

func (ClientType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{4}
}

type AuthenticationType int32

const (
	AuthenticationType_SELFSIGNED AuthenticationType = 0
	AuthenticationType_CASIGNED   AuthenticationType = 1
)

var AuthenticationType_name = map[int32]string{
	0: "SELFSIGNED",
	1: "CASIGNED",
}

var AuthenticationType_value = map[string]int32{
	"SELFSIGNED": 0,
	"CASIGNED":   1,
}

func (x AuthenticationType) String() string {
	return proto.EnumName(AuthenticationType_name, int32(x))
}

func (AuthenticationType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{5}
}

type ProviderType int32

const (
	ProviderType_AnyProvider            ProviderType = 0
	ProviderType_VirtualMachine         ProviderType = 1
	ProviderType_VirtualMachineScaleSet ProviderType = 2
	ProviderType_LoadBalancer           ProviderType = 3
	ProviderType_VirtualNetwork         ProviderType = 4
	ProviderType_VirtualHardDisk        ProviderType = 5
	ProviderType_GalleryImage           ProviderType = 6
	ProviderType_VirtualMachineImage    ProviderType = 7
	ProviderType_NetworkInterface       ProviderType = 8
	ProviderType_KeyVault               ProviderType = 9
	ProviderType_Kubernetes             ProviderType = 10
	ProviderType_Cluster                ProviderType = 11
	ProviderType_ControlPlane           ProviderType = 12
	ProviderType_Group                  ProviderType = 13
	ProviderType_Node                   ProviderType = 14
	ProviderType_Location               ProviderType = 15
	ProviderType_StorageContainer       ProviderType = 16
	ProviderType_StorageFile            ProviderType = 17
	ProviderType_StorageDirectory       ProviderType = 18
	ProviderType_Subscription           ProviderType = 19
	ProviderType_VipPool                ProviderType = 20
	ProviderType_MacPool                ProviderType = 21
	ProviderType_EtcdCluster            ProviderType = 22
	ProviderType_BareMetalMachine       ProviderType = 23
)

var ProviderType_name = map[int32]string{
	0:  "AnyProvider",
	1:  "VirtualMachine",
	2:  "VirtualMachineScaleSet",
	3:  "LoadBalancer",
	4:  "VirtualNetwork",
	5:  "VirtualHardDisk",
	6:  "GalleryImage",
	7:  "VirtualMachineImage",
	8:  "NetworkInterface",
	9:  "KeyVault",
	10: "Kubernetes",
	11: "Cluster",
	12: "ControlPlane",
	13: "Group",
	14: "Node",
	15: "Location",
	16: "StorageContainer",
	17: "StorageFile",
	18: "StorageDirectory",
	19: "Subscription",
	20: "VipPool",
	21: "MacPool",
	22: "EtcdCluster",
	23: "BareMetalMachine",
}

var ProviderType_value = map[string]int32{
	"AnyProvider":            0,
	"VirtualMachine":         1,
	"VirtualMachineScaleSet": 2,
	"LoadBalancer":           3,
	"VirtualNetwork":         4,
	"VirtualHardDisk":        5,
	"GalleryImage":           6,
	"VirtualMachineImage":    7,
	"NetworkInterface":       8,
	"KeyVault":               9,
	"Kubernetes":             10,
	"Cluster":                11,
	"ControlPlane":           12,
	"Group":                  13,
	"Node":                   14,
	"Location":               15,
	"StorageContainer":       16,
	"StorageFile":            17,
	"StorageDirectory":       18,
	"Subscription":           19,
	"VipPool":                20,
	"MacPool":                21,
	"EtcdCluster":            22,
	"BareMetalMachine":       23,
}

func (x ProviderType) String() string {
	return proto.EnumName(ProviderType_name, int32(x))
}

func (ProviderType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{6}
}

type Error struct {
	Message              string   `protobuf:"bytes,1,opt,name=Message,proto3" json:"Message,omitempty"`
	Code                 int32    `protobuf:"varint,2,opt,name=Code,proto3" json:"Code,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Error) Reset()         { *m = Error{} }
func (m *Error) String() string { return proto.CompactTextString(m) }
func (*Error) ProtoMessage()    {}
func (*Error) Descriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{0}
}

func (m *Error) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Error.Unmarshal(m, b)
}
func (m *Error) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Error.Marshal(b, m, deterministic)
}
func (m *Error) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Error.Merge(m, src)
}
func (m *Error) XXX_Size() int {
	return xxx_messageInfo_Error.Size(m)
}
func (m *Error) XXX_DiscardUnknown() {
	xxx_messageInfo_Error.DiscardUnknown(m)
}

var xxx_messageInfo_Error proto.InternalMessageInfo

func (m *Error) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *Error) GetCode() int32 {
	if m != nil {
		return m.Code
	}
	return 0
}

type ProvisionStatus struct {
	CurrentState         ProvisionState `protobuf:"varint,1,opt,name=currentState,proto3,enum=moc.ProvisionState" json:"currentState,omitempty"`
	PreviousState        ProvisionState `protobuf:"varint,2,opt,name=previousState,proto3,enum=moc.ProvisionState" json:"previousState,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *ProvisionStatus) Reset()         { *m = ProvisionStatus{} }
func (m *ProvisionStatus) String() string { return proto.CompactTextString(m) }
func (*ProvisionStatus) ProtoMessage()    {}
func (*ProvisionStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{1}
}

func (m *ProvisionStatus) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProvisionStatus.Unmarshal(m, b)
}
func (m *ProvisionStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProvisionStatus.Marshal(b, m, deterministic)
}
func (m *ProvisionStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProvisionStatus.Merge(m, src)
}
func (m *ProvisionStatus) XXX_Size() int {
	return xxx_messageInfo_ProvisionStatus.Size(m)
}
func (m *ProvisionStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_ProvisionStatus.DiscardUnknown(m)
}

var xxx_messageInfo_ProvisionStatus proto.InternalMessageInfo

func (m *ProvisionStatus) GetCurrentState() ProvisionState {
	if m != nil {
		return m.CurrentState
	}
	return ProvisionState_UNKNOWN
}

func (m *ProvisionStatus) GetPreviousState() ProvisionState {
	if m != nil {
		return m.PreviousState
	}
	return ProvisionState_UNKNOWN
}

type Health struct {
	CurrentState         HealthState `protobuf:"varint,1,opt,name=currentState,proto3,enum=moc.HealthState" json:"currentState,omitempty"`
	PreviousState        HealthState `protobuf:"varint,2,opt,name=previousState,proto3,enum=moc.HealthState" json:"previousState,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *Health) Reset()         { *m = Health{} }
func (m *Health) String() string { return proto.CompactTextString(m) }
func (*Health) ProtoMessage()    {}
func (*Health) Descriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{2}
}

func (m *Health) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Health.Unmarshal(m, b)
}
func (m *Health) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Health.Marshal(b, m, deterministic)
}
func (m *Health) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Health.Merge(m, src)
}
func (m *Health) XXX_Size() int {
	return xxx_messageInfo_Health.Size(m)
}
func (m *Health) XXX_DiscardUnknown() {
	xxx_messageInfo_Health.DiscardUnknown(m)
}

var xxx_messageInfo_Health proto.InternalMessageInfo

func (m *Health) GetCurrentState() HealthState {
	if m != nil {
		return m.CurrentState
	}
	return HealthState_NOTKNOWN
}

func (m *Health) GetPreviousState() HealthState {
	if m != nil {
		return m.PreviousState
	}
	return HealthState_NOTKNOWN
}

type Version struct {
	Number               string   `protobuf:"bytes,1,opt,name=number,proto3" json:"number,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Version) Reset()         { *m = Version{} }
func (m *Version) String() string { return proto.CompactTextString(m) }
func (*Version) ProtoMessage()    {}
func (*Version) Descriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{3}
}

func (m *Version) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Version.Unmarshal(m, b)
}
func (m *Version) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Version.Marshal(b, m, deterministic)
}
func (m *Version) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Version.Merge(m, src)
}
func (m *Version) XXX_Size() int {
	return xxx_messageInfo_Version.Size(m)
}
func (m *Version) XXX_DiscardUnknown() {
	xxx_messageInfo_Version.DiscardUnknown(m)
}

var xxx_messageInfo_Version proto.InternalMessageInfo

func (m *Version) GetNumber() string {
	if m != nil {
		return m.Number
	}
	return ""
}

type Status struct {
	Health               *Health          `protobuf:"bytes,1,opt,name=health,proto3" json:"health,omitempty"`
	ProvisioningStatus   *ProvisionStatus `protobuf:"bytes,2,opt,name=provisioningStatus,proto3" json:"provisioningStatus,omitempty"`
	LastError            *Error           `protobuf:"bytes,3,opt,name=lastError,proto3" json:"lastError,omitempty"`
	Version              *Version         `protobuf:"bytes,4,opt,name=version,proto3" json:"version,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *Status) Reset()         { *m = Status{} }
func (m *Status) String() string { return proto.CompactTextString(m) }
func (*Status) ProtoMessage()    {}
func (*Status) Descriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{4}
}

func (m *Status) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Status.Unmarshal(m, b)
}
func (m *Status) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Status.Marshal(b, m, deterministic)
}
func (m *Status) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Status.Merge(m, src)
}
func (m *Status) XXX_Size() int {
	return xxx_messageInfo_Status.Size(m)
}
func (m *Status) XXX_DiscardUnknown() {
	xxx_messageInfo_Status.DiscardUnknown(m)
}

var xxx_messageInfo_Status proto.InternalMessageInfo

func (m *Status) GetHealth() *Health {
	if m != nil {
		return m.Health
	}
	return nil
}

func (m *Status) GetProvisioningStatus() *ProvisionStatus {
	if m != nil {
		return m.ProvisioningStatus
	}
	return nil
}

func (m *Status) GetLastError() *Error {
	if m != nil {
		return m.LastError
	}
	return nil
}

func (m *Status) GetVersion() *Version {
	if m != nil {
		return m.Version
	}
	return nil
}

type Entity struct {
	IsPlaceholder        bool     `protobuf:"varint,1,opt,name=IsPlaceholder,proto3" json:"IsPlaceholder,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Entity) Reset()         { *m = Entity{} }
func (m *Entity) String() string { return proto.CompactTextString(m) }
func (*Entity) ProtoMessage()    {}
func (*Entity) Descriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{5}
}

func (m *Entity) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Entity.Unmarshal(m, b)
}
func (m *Entity) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Entity.Marshal(b, m, deterministic)
}
func (m *Entity) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Entity.Merge(m, src)
}
func (m *Entity) XXX_Size() int {
	return xxx_messageInfo_Entity.Size(m)
}
func (m *Entity) XXX_DiscardUnknown() {
	xxx_messageInfo_Entity.DiscardUnknown(m)
}

var xxx_messageInfo_Entity proto.InternalMessageInfo

func (m *Entity) GetIsPlaceholder() bool {
	if m != nil {
		return m.IsPlaceholder
	}
	return false
}

type Tag struct {
	Key                  string   `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value                string   `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Tag) Reset()         { *m = Tag{} }
func (m *Tag) String() string { return proto.CompactTextString(m) }
func (*Tag) ProtoMessage()    {}
func (*Tag) Descriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{6}
}

func (m *Tag) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Tag.Unmarshal(m, b)
}
func (m *Tag) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Tag.Marshal(b, m, deterministic)
}
func (m *Tag) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Tag.Merge(m, src)
}
func (m *Tag) XXX_Size() int {
	return xxx_messageInfo_Tag.Size(m)
}
func (m *Tag) XXX_DiscardUnknown() {
	xxx_messageInfo_Tag.DiscardUnknown(m)
}

var xxx_messageInfo_Tag proto.InternalMessageInfo

func (m *Tag) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *Tag) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type Tags struct {
	Tags                 []*Tag   `protobuf:"bytes,1,rep,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Tags) Reset()         { *m = Tags{} }
func (m *Tags) String() string { return proto.CompactTextString(m) }
func (*Tags) ProtoMessage()    {}
func (*Tags) Descriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{7}
}

func (m *Tags) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Tags.Unmarshal(m, b)
}
func (m *Tags) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Tags.Marshal(b, m, deterministic)
}
func (m *Tags) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Tags.Merge(m, src)
}
func (m *Tags) XXX_Size() int {
	return xxx_messageInfo_Tags.Size(m)
}
func (m *Tags) XXX_DiscardUnknown() {
	xxx_messageInfo_Tags.DiscardUnknown(m)
}

var xxx_messageInfo_Tags proto.InternalMessageInfo

func (m *Tags) GetTags() []*Tag {
	if m != nil {
		return m.Tags
	}
	return nil
}

func init() {
	proto.RegisterEnum("moc.Operation", Operation_name, Operation_value)
	proto.RegisterEnum("moc.ProvisionState", ProvisionState_name, ProvisionState_value)
	proto.RegisterEnum("moc.HighAvailabilityState", HighAvailabilityState_name, HighAvailabilityState_value)
	proto.RegisterEnum("moc.HealthState", HealthState_name, HealthState_value)
	proto.RegisterEnum("moc.ClientType", ClientType_name, ClientType_value)
	proto.RegisterEnum("moc.AuthenticationType", AuthenticationType_name, AuthenticationType_value)
	proto.RegisterEnum("moc.ProviderType", ProviderType_name, ProviderType_value)
	proto.RegisterType((*Error)(nil), "moc.Error")
	proto.RegisterType((*ProvisionStatus)(nil), "moc.ProvisionStatus")
	proto.RegisterType((*Health)(nil), "moc.Health")
	proto.RegisterType((*Version)(nil), "moc.Version")
	proto.RegisterType((*Status)(nil), "moc.Status")
	proto.RegisterType((*Entity)(nil), "moc.Entity")
	proto.RegisterType((*Tag)(nil), "moc.Tag")
	proto.RegisterType((*Tags)(nil), "moc.Tags")
}

func init() { proto.RegisterFile("moc_common_common.proto", fileDescriptor_681f78e46755eb93) }

var fileDescriptor_681f78e46755eb93 = []byte{
	// 1020 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x55, 0x5f, 0x6f, 0xe2, 0xc6,
	0x17, 0x5d, 0x30, 0x7f, 0x2f, 0x04, 0x66, 0x27, 0xd9, 0x2c, 0xfa, 0xe9, 0xf7, 0x90, 0xb2, 0xdb,
	0x2a, 0x42, 0x6a, 0x22, 0xa5, 0xed, 0x56, 0x7d, 0x74, 0xb0, 0x43, 0xac, 0x10, 0x1b, 0xd9, 0x4e,
	0xb6, 0xea, 0x4b, 0x34, 0x98, 0x59, 0x63, 0xc5, 0x78, 0xd0, 0x78, 0x4c, 0xc5, 0x07, 0xe8, 0xe7,
	0xe8, 0x07, 0xe9, 0x73, 0xbf, 0x57, 0x35, 0x33, 0x66, 0x17, 0xba, 0xe9, 0x13, 0x9e, 0x33, 0xe7,
	0x9c, 0x7b, 0xef, 0xf1, 0x45, 0x86, 0xb7, 0x2b, 0x16, 0x3d, 0x45, 0x6c, 0xb5, 0x62, 0x59, 0xf9,
	0x73, 0xb1, 0xe6, 0x4c, 0x30, 0x6c, 0xac, 0x58, 0x34, 0xfc, 0x09, 0xea, 0x36, 0xe7, 0x8c, 0xe3,
	0x01, 0x34, 0xef, 0x69, 0x9e, 0x93, 0x98, 0x0e, 0x2a, 0x67, 0x95, 0xf3, 0xb6, 0xbf, 0x3b, 0x62,
	0x0c, 0xb5, 0x31, 0x5b, 0xd0, 0x41, 0xf5, 0xac, 0x72, 0x5e, 0xf7, 0xd5, 0xf3, 0xf0, 0x8f, 0x0a,
	0xf4, 0x67, 0x9c, 0x6d, 0x92, 0x3c, 0x61, 0x59, 0x20, 0x88, 0x28, 0x72, 0xfc, 0x33, 0x74, 0xa3,
	0x82, 0x73, 0x9a, 0x09, 0x09, 0x68, 0x9b, 0xde, 0xd5, 0xf1, 0xc5, 0x8a, 0x45, 0x17, 0x07, 0x5c,
	0xea, 0x1f, 0x10, 0xf1, 0x2f, 0x70, 0xb4, 0xe6, 0x74, 0x93, 0xb0, 0x22, 0xd7, 0xca, 0xea, 0x7f,
	0x2b, 0x0f, 0x99, 0xc3, 0x0d, 0x34, 0x6e, 0x29, 0x49, 0xc5, 0x12, 0xff, 0xf8, 0x62, 0x75, 0xa4,
	0x3c, 0x34, 0xe5, 0xa5, 0xd2, 0x1f, 0x5e, 0x2e, 0xfd, 0xb5, 0xec, 0x5f, 0x75, 0xbf, 0x81, 0xe6,
	0x23, 0xe5, 0xb2, 0x2d, 0x7c, 0x0a, 0x8d, 0xac, 0x58, 0xcd, 0x29, 0x2f, 0x73, 0x2b, 0x4f, 0xc3,
	0xbf, 0x2b, 0xd0, 0x28, 0x93, 0x79, 0x07, 0x8d, 0xa5, 0xf2, 0x52, 0x94, 0xce, 0x55, 0x67, 0xcf,
	0xde, 0x2f, 0xaf, 0xb0, 0x05, 0x78, 0xbd, 0x9b, 0x35, 0xc9, 0x62, 0x2d, 0x55, 0xfd, 0x74, 0xae,
	0x4e, 0xbe, 0x8e, 0xa2, 0xc8, 0xfd, 0x17, 0xf8, 0xf8, 0x1c, 0xda, 0x29, 0xc9, 0x85, 0x7a, 0xa7,
	0x03, 0x43, 0x89, 0x41, 0x89, 0x15, 0xe2, 0x7f, 0xb9, 0xc4, 0xdf, 0x41, 0x73, 0xa3, 0x47, 0x18,
	0xd4, 0x14, 0xaf, 0xab, 0x78, 0xe5, 0x58, 0xfe, 0xee, 0x72, 0x78, 0x01, 0x0d, 0x3b, 0x13, 0x89,
	0xd8, 0xe2, 0xf7, 0x70, 0xe4, 0xe4, 0xb3, 0x94, 0x44, 0x74, 0xc9, 0xd2, 0x45, 0x39, 0x70, 0xcb,
	0x3f, 0x04, 0x87, 0xdf, 0x83, 0x11, 0x92, 0x18, 0x23, 0x30, 0x9e, 0xe9, 0xb6, 0xcc, 0x44, 0x3e,
	0xe2, 0x13, 0xa8, 0x6f, 0x48, 0x5a, 0xe8, 0x8c, 0xdb, 0xbe, 0x3e, 0x0c, 0xdf, 0x43, 0x2d, 0x24,
	0x71, 0x8e, 0xff, 0x0f, 0x35, 0x41, 0xe2, 0x7c, 0x50, 0x39, 0x33, 0xce, 0x3b, 0x57, 0x2d, 0xd5,
	0x4b, 0x48, 0x62, 0x5f, 0xa1, 0xa3, 0x0f, 0xd0, 0xf6, 0xd6, 0x94, 0x13, 0x21, 0x13, 0x6f, 0x82,
	0x31, 0xb1, 0x43, 0xf4, 0x0a, 0xb7, 0xa0, 0x36, 0xf3, 0x82, 0x10, 0x55, 0x30, 0x40, 0xc3, 0xb2,
	0xa7, 0x76, 0x68, 0xa3, 0xaa, 0x7c, 0x7e, 0x98, 0x59, 0x66, 0x68, 0x23, 0x63, 0xf4, 0x67, 0x15,
	0x7a, 0x87, 0x1b, 0x84, 0x3b, 0xd0, 0x7c, 0x70, 0xef, 0x5c, 0xef, 0xa3, 0x8b, 0x5e, 0xe1, 0x2e,
	0xb4, 0xc6, 0xbe, 0x6d, 0x86, 0x8e, 0x3b, 0x41, 0x15, 0x79, 0xa5, 0x4e, 0xb6, 0x85, 0xaa, 0xf8,
	0x35, 0x1c, 0xe9, 0xc3, 0xd3, 0x8d, 0xe9, 0x4c, 0x6d, 0x0b, 0x19, 0x92, 0xad, 0xaa, 0x48, 0x76,
	0x4d, 0x12, 0x74, 0xcd, 0x1d, 0xa1, 0x2e, 0x0d, 0x34, 0x64, 0xa1, 0x86, 0x64, 0xab, 0x3e, 0x24,
	0xbb, 0x29, 0xd9, 0xba, 0xab, 0x1d, 0xbb, 0xa5, 0x3a, 0x51, 0x90, 0x85, 0xda, 0x18, 0x41, 0x77,
	0xe6, 0x7b, 0x8f, 0x4e, 0xe0, 0x78, 0xae, 0x54, 0x00, 0xee, 0x43, 0xe7, 0x33, 0x62, 0x5b, 0xa8,
	0x83, 0x4f, 0x00, 0x7d, 0x06, 0x76, 0x2e, 0x5d, 0x8c, 0xa1, 0x67, 0xd9, 0x07, 0xd2, 0x23, 0xdd,
	0xda, 0xbe, 0xb8, 0x87, 0x4f, 0x01, 0xef, 0x41, 0x3b, 0x79, 0x7f, 0x74, 0x03, 0x6f, 0x6e, 0x93,
	0x78, 0x69, 0x6e, 0x48, 0x92, 0x92, 0x79, 0x92, 0x26, 0x62, 0xab, 0x73, 0x3a, 0x01, 0x54, 0xe6,
	0xf4, 0x74, 0x6b, 0x3e, 0x05, 0xa1, 0x0c, 0xf4, 0x95, 0x0c, 0x37, 0x08, 0xcd, 0xeb, 0xa9, 0xad,
	0xe3, 0x9a, 0xd9, 0xae, 0x25, 0x4b, 0x56, 0x47, 0x31, 0x74, 0xf6, 0xfe, 0x2f, 0x72, 0x78, 0xd7,
	0x0b, 0x77, 0x31, 0x37, 0xa0, 0xea, 0xdd, 0x69, 0xc5, 0x47, 0xd3, 0x57, 0x4d, 0x56, 0x75, 0xf6,
	0x4e, 0xe8, 0x8c, 0xcd, 0x29, 0x32, 0xe4, 0xd5, 0xbd, 0x13, 0x04, 0x3a, 0x5a, 0x15, 0xf4, 0xc4,
	0x37, 0x2d, 0x95, 0xaa, 0xf6, 0xba, 0xf1, 0x1e, 0x5c, 0x0b, 0x35, 0x46, 0x13, 0x80, 0x71, 0x9a,
	0xd0, 0x4c, 0x84, 0xdb, 0x35, 0x95, 0xb1, 0x8d, 0x3d, 0x37, 0xf4, 0xbd, 0xe9, 0x6c, 0x6a, 0xba,
	0xb2, 0x43, 0x0c, 0x3d, 0xfb, 0xd7, 0xd0, 0xf6, 0x5d, 0x73, 0x3a, 0x9e, 0x3a, 0xb6, 0x2b, 0xd7,
	0xa3, 0x05, 0x35, 0xd7, 0xb3, 0xe4, 0x72, 0xb4, 0xa1, 0x6e, 0x5a, 0xf7, 0x8e, 0x8b, 0x8c, 0xd1,
	0x15, 0x60, 0xb3, 0x10, 0x4b, 0x9a, 0x89, 0x24, 0x52, 0x8b, 0xa5, 0x0c, 0x7b, 0x00, 0x81, 0x3d,
	0xbd, 0x09, 0x9c, 0x89, 0xcc, 0x4d, 0x6f, 0x88, 0x59, 0x9e, 0x2a, 0xa3, 0xbf, 0x0c, 0xe8, 0xaa,
	0x7d, 0x5a, 0x50, 0xae, 0xe8, 0x7d, 0xe8, 0x98, 0xd9, 0x76, 0x07, 0xe9, 0xf2, 0x8f, 0x09, 0x17,
	0x05, 0x49, 0xef, 0x49, 0xb4, 0x4c, 0x32, 0x8a, 0x2a, 0xf8, 0x7f, 0x70, 0x7a, 0x88, 0x05, 0x11,
	0x49, 0x69, 0x40, 0x05, 0xaa, 0xca, 0x01, 0xa6, 0x8c, 0x2c, 0xae, 0x49, 0x4a, 0xb2, 0x88, 0x72,
	0x64, 0xec, 0x39, 0xb8, 0x54, 0xfc, 0xce, 0xf8, 0x33, 0xaa, 0xe1, 0x63, 0xe8, 0x97, 0xd8, 0x2d,
	0xe1, 0x0b, 0x2b, 0xc9, 0x9f, 0x51, 0x5d, 0x4a, 0x27, 0x24, 0x4d, 0x29, 0xdf, 0x3a, 0x2b, 0x12,
	0x53, 0xd4, 0xc0, 0x6f, 0xe1, 0xf8, 0xb0, 0x90, 0xbe, 0x68, 0xca, 0x97, 0x59, 0x9a, 0x39, 0x99,
	0xa0, 0xfc, 0x13, 0x89, 0x28, 0x6a, 0xc9, 0xd9, 0xee, 0xe8, 0xf6, 0x91, 0x14, 0xa9, 0x40, 0x6d,
	0x39, 0xf9, 0x5d, 0x31, 0xa7, 0x3c, 0xa3, 0x82, 0xe6, 0x08, 0xd4, 0xbf, 0x21, 0x2d, 0x72, 0x41,
	0x39, 0xea, 0xa8, 0x9c, 0x59, 0x26, 0x38, 0x4b, 0x67, 0x29, 0xc9, 0x28, 0xea, 0xca, 0x24, 0x27,
	0x9c, 0x15, 0x6b, 0x74, 0xa4, 0xe2, 0x65, 0x0b, 0x8a, 0x7a, 0xd2, 0x71, 0xca, 0x74, 0x9a, 0xa8,
	0x2f, 0xab, 0x06, 0x82, 0x71, 0x12, 0x53, 0xa9, 0x25, 0x49, 0x46, 0x39, 0x42, 0x32, 0xb2, 0x12,
	0xbd, 0x49, 0x52, 0x8a, 0x5e, 0xef, 0xd1, 0xac, 0x84, 0xd3, 0x48, 0x30, 0xbe, 0x45, 0x58, 0x56,
	0x0c, 0x8a, 0x79, 0x1e, 0xf1, 0x64, 0xad, 0xec, 0x8e, 0x65, 0x43, 0x8f, 0xc9, 0x7a, 0xc6, 0x58,
	0x8a, 0x4e, 0xd4, 0xbe, 0x90, 0x48, 0x1d, 0xde, 0x48, 0x4b, 0x5b, 0x44, 0x8b, 0x5d, 0xbb, 0xa7,
	0xd2, 0xf2, 0x9a, 0x70, 0x7a, 0x4f, 0xc5, 0x97, 0xf7, 0xf0, 0xf6, 0xfa, 0xdb, 0xdf, 0xde, 0xc5,
	0x89, 0x58, 0x16, 0xf3, 0x8b, 0x88, 0xad, 0x2e, 0x57, 0x49, 0xc4, 0x59, 0xce, 0x3e, 0x89, 0xcb,
	0x15, 0x8b, 0x2e, 0xf9, 0x3a, 0xba, 0xd4, 0x9f, 0xc7, 0x79, 0x43, 0x7d, 0x1f, 0x7f, 0xf8, 0x27,
	0x00, 0x00, 0xff, 0xff, 0xb9, 0x05, 0x9f, 0xb5, 0x3a, 0x07, 0x00, 0x00,
}
