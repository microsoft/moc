// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_common_common.proto

package common

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	descriptor "github.com/golang/protobuf/protoc-gen-go/descriptor"
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
	ProvisionState_DELETE_PENDING     ProvisionState = 16
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
	16: "DELETE_PENDING",
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
	"DELETE_PENDING":     16,
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
	ClientType_BAREMETAL      ClientType = 4
	ClientType_LOADBALANCER   ClientType = 5
)

var ClientType_name = map[int32]string{
	0: "CONTROLPLANE",
	1: "EXTERNALCLIENT",
	2: "NODE",
	3: "ADMIN",
	4: "BAREMETAL",
	5: "LOADBALANCER",
}

var ClientType_value = map[string]int32{
	"CONTROLPLANE":   0,
	"EXTERNALCLIENT": 1,
	"NODE":           2,
	"ADMIN":          3,
	"BAREMETAL":      4,
	"LOADBALANCER":   5,
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
	ProviderType_Certificate            ProviderType = 9
	ProviderType_Key                    ProviderType = 10
	ProviderType_Secret                 ProviderType = 11
	ProviderType_KeyVault               ProviderType = 12
	ProviderType_Identity               ProviderType = 13
	ProviderType_Role                   ProviderType = 14
	ProviderType_RoleAssignment         ProviderType = 15
	ProviderType_Kubernetes             ProviderType = 16
	ProviderType_Cluster                ProviderType = 17
	ProviderType_ControlPlane           ProviderType = 18
	ProviderType_Group                  ProviderType = 19
	ProviderType_Node                   ProviderType = 20
	ProviderType_Location               ProviderType = 21
	ProviderType_StorageContainer       ProviderType = 22
	ProviderType_StorageFile            ProviderType = 23
	ProviderType_StorageDirectory       ProviderType = 24
	ProviderType_Subscription           ProviderType = 25
	ProviderType_VipPool                ProviderType = 26
	ProviderType_MacPool                ProviderType = 27
	ProviderType_EtcdCluster            ProviderType = 28
	ProviderType_EtcdServer             ProviderType = 29
	ProviderType_BareMetalMachine       ProviderType = 30
	ProviderType_CredentialMonitor      ProviderType = 31
	ProviderType_Logging                ProviderType = 32
	ProviderType_Recovery               ProviderType = 33
	ProviderType_Debug                  ProviderType = 34
	ProviderType_BareMetalHost          ProviderType = 35
	ProviderType_Authentication         ProviderType = 36
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
	9:  "Certificate",
	10: "Key",
	11: "Secret",
	12: "KeyVault",
	13: "Identity",
	14: "Role",
	15: "RoleAssignment",
	16: "Kubernetes",
	17: "Cluster",
	18: "ControlPlane",
	19: "Group",
	20: "Node",
	21: "Location",
	22: "StorageContainer",
	23: "StorageFile",
	24: "StorageDirectory",
	25: "Subscription",
	26: "VipPool",
	27: "MacPool",
	28: "EtcdCluster",
	29: "EtcdServer",
	30: "BareMetalMachine",
	31: "CredentialMonitor",
	32: "Logging",
	33: "Recovery",
	34: "Debug",
	35: "BareMetalHost",
	36: "Authentication",
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
	"Certificate":            9,
	"Key":                    10,
	"Secret":                 11,
	"KeyVault":               12,
	"Identity":               13,
	"Role":                   14,
	"RoleAssignment":         15,
	"Kubernetes":             16,
	"Cluster":                17,
	"ControlPlane":           18,
	"Group":                  19,
	"Node":                   20,
	"Location":               21,
	"StorageContainer":       22,
	"StorageFile":            23,
	"StorageDirectory":       24,
	"Subscription":           25,
	"VipPool":                26,
	"MacPool":                27,
	"EtcdCluster":            28,
	"EtcdServer":             29,
	"BareMetalMachine":       30,
	"CredentialMonitor":      31,
	"Logging":                32,
	"Recovery":               33,
	"Debug":                  34,
	"BareMetalHost":          35,
	"Authentication":         36,
}

func (x ProviderType) String() string {
	return proto.EnumName(ProviderType_name, int32(x))
}

func (ProviderType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{6}
}

type ImageSource int32

const (
	ImageSource_LOCAL_SOURCE ImageSource = 0
	ImageSource_SFS_SOURCE   ImageSource = 1
	ImageSource_HTTP_SOURCE  ImageSource = 2
	ImageSource_CLONE_SOURCE ImageSource = 3
)

var ImageSource_name = map[int32]string{
	0: "LOCAL_SOURCE",
	1: "SFS_SOURCE",
	2: "HTTP_SOURCE",
	3: "CLONE_SOURCE",
}

var ImageSource_value = map[string]int32{
	"LOCAL_SOURCE": 0,
	"SFS_SOURCE":   1,
	"HTTP_SOURCE":  2,
	"CLONE_SOURCE": 3,
}

func (x ImageSource) String() string {
	return proto.EnumName(ImageSource_name, int32(x))
}

func (ImageSource) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{7}
}

type CloudInitDataSource int32

const (
	CloudInitDataSource_Azure   CloudInitDataSource = 0
	CloudInitDataSource_NoCloud CloudInitDataSource = 1
)

var CloudInitDataSource_name = map[int32]string{
	0: "Azure",
	1: "NoCloud",
}

var CloudInitDataSource_value = map[string]int32{
	"Azure":   0,
	"NoCloud": 1,
}

func (x CloudInitDataSource) String() string {
	return proto.EnumName(CloudInitDataSource_name, int32(x))
}

func (CloudInitDataSource) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{8}
}

type HyperVGeneration int32

const (
	HyperVGeneration_V1 HyperVGeneration = 0
	HyperVGeneration_V2 HyperVGeneration = 1
)

var HyperVGeneration_name = map[int32]string{
	0: "V1",
	1: "V2",
}

var HyperVGeneration_value = map[string]int32{
	"V1": 0,
	"V2": 1,
}

func (x HyperVGeneration) String() string {
	return proto.EnumName(HyperVGeneration_name, int32(x))
}

func (HyperVGeneration) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_681f78e46755eb93, []int{9}
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

var E_Sensitive = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         50001,
	Name:          "moc.sensitive",
	Tag:           "varint,50001,opt,name=sensitive",
	Filename:      "moc_common_common.proto",
}

func init() {
	proto.RegisterEnum("moc.Operation", Operation_name, Operation_value)
	proto.RegisterEnum("moc.ProvisionState", ProvisionState_name, ProvisionState_value)
	proto.RegisterEnum("moc.HighAvailabilityState", HighAvailabilityState_name, HighAvailabilityState_value)
	proto.RegisterEnum("moc.HealthState", HealthState_name, HealthState_value)
	proto.RegisterEnum("moc.ClientType", ClientType_name, ClientType_value)
	proto.RegisterEnum("moc.AuthenticationType", AuthenticationType_name, AuthenticationType_value)
	proto.RegisterEnum("moc.ProviderType", ProviderType_name, ProviderType_value)
	proto.RegisterEnum("moc.ImageSource", ImageSource_name, ImageSource_value)
	proto.RegisterEnum("moc.CloudInitDataSource", CloudInitDataSource_name, CloudInitDataSource_value)
	proto.RegisterEnum("moc.HyperVGeneration", HyperVGeneration_name, HyperVGeneration_value)
	proto.RegisterType((*Error)(nil), "moc.Error")
	proto.RegisterType((*ProvisionStatus)(nil), "moc.ProvisionStatus")
	proto.RegisterType((*Health)(nil), "moc.Health")
	proto.RegisterType((*Version)(nil), "moc.Version")
	proto.RegisterType((*Status)(nil), "moc.Status")
	proto.RegisterType((*Entity)(nil), "moc.Entity")
	proto.RegisterType((*Tag)(nil), "moc.Tag")
	proto.RegisterType((*Tags)(nil), "moc.Tags")
	proto.RegisterExtension(E_Sensitive)
}

func init() { proto.RegisterFile("moc_common_common.proto", fileDescriptor_681f78e46755eb93) }

var fileDescriptor_681f78e46755eb93 = []byte{
	// 1328 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x56, 0x5f, 0x6f, 0xdb, 0xc8,
	0x11, 0xb7, 0xfe, 0xda, 0x1a, 0xf9, 0xcf, 0x66, 0xed, 0x38, 0x6a, 0x9a, 0xb4, 0x8e, 0x92, 0x16,
	0x86, 0x80, 0xc8, 0xa8, 0xdb, 0xa6, 0x68, 0x81, 0x3e, 0xd0, 0x22, 0x6d, 0x0b, 0xa6, 0x49, 0x81,
	0xa4, 0x95, 0xc3, 0xbd, 0x18, 0x2b, 0x6a, 0x4c, 0x11, 0xa1, 0xb8, 0xc2, 0x72, 0xa9, 0x83, 0xee,
	0xed, 0x1e, 0xee, 0xbe, 0xd0, 0x7d, 0x86, 0xfb, 0x00, 0xf7, 0x8d, 0x0e, 0xbb, 0x14, 0x13, 0xeb,
	0xe2, 0x7b, 0x12, 0x67, 0xf6, 0x37, 0xbf, 0x99, 0xf9, 0xcd, 0x2c, 0x45, 0x78, 0x31, 0xe7, 0xe1,
	0x7d, 0xc8, 0xe7, 0x73, 0x9e, 0xae, 0x7f, 0xfa, 0x0b, 0xc1, 0x25, 0xa7, 0xb5, 0x39, 0x0f, 0x5f,
	0x9e, 0x44, 0x9c, 0x47, 0x09, 0x9e, 0x69, 0xd7, 0x24, 0x7f, 0x38, 0x9b, 0x62, 0x16, 0x8a, 0x78,
	0x21, 0xb9, 0x28, 0x60, 0xdd, 0x7f, 0x43, 0xc3, 0x12, 0x82, 0x0b, 0xda, 0x81, 0xed, 0x5b, 0xcc,
	0x32, 0x16, 0x61, 0xa7, 0x72, 0x52, 0x39, 0x6d, 0x79, 0xa5, 0x49, 0x29, 0xd4, 0x07, 0x7c, 0x8a,
	0x9d, 0xea, 0x49, 0xe5, 0xb4, 0xe1, 0xe9, 0xe7, 0xee, 0x8f, 0x15, 0x38, 0x18, 0x09, 0xbe, 0x8c,
	0xb3, 0x98, 0xa7, 0xbe, 0x64, 0x32, 0xcf, 0xe8, 0x7f, 0x60, 0x37, 0xcc, 0x85, 0xc0, 0x54, 0x2a,
	0x47, 0x41, 0xb3, 0x7f, 0x7e, 0xd8, 0x9f, 0xf3, 0xb0, 0xbf, 0x81, 0x45, 0x6f, 0x03, 0x48, 0xff,
	0x0b, 0x7b, 0x0b, 0x81, 0xcb, 0x98, 0xe7, 0x59, 0x11, 0x59, 0xfd, 0xe3, 0xc8, 0x4d, 0x64, 0x77,
	0x09, 0xcd, 0x6b, 0x64, 0x89, 0x9c, 0xd1, 0x7f, 0x3d, 0x99, 0x9d, 0x68, 0x8e, 0x02, 0xf2, 0x54,
	0xea, 0x0f, 0x4f, 0xa7, 0xfe, 0x3a, 0xec, 0x77, 0x79, 0xdf, 0xc0, 0xf6, 0x18, 0x85, 0x2a, 0x8b,
	0x1e, 0x43, 0x33, 0xcd, 0xe7, 0x13, 0x14, 0x6b, 0xdd, 0xd6, 0x56, 0xf7, 0x97, 0x0a, 0x34, 0xd7,
	0xca, 0xbc, 0x85, 0xe6, 0x4c, 0x73, 0x69, 0x48, 0xfb, 0xbc, 0xfd, 0x88, 0xde, 0x5b, 0x1f, 0x51,
	0x13, 0xe8, 0xa2, 0xec, 0x35, 0x4e, 0xa3, 0x22, 0x54, 0xd7, 0xd3, 0x3e, 0x3f, 0xfa, 0x5a, 0x8a,
	0x3c, 0xf3, 0x9e, 0xc0, 0xd3, 0x53, 0x68, 0x25, 0x2c, 0x93, 0x7a, 0xa6, 0x9d, 0x9a, 0x0e, 0x06,
	0x1d, 0xac, 0x3d, 0xde, 0x97, 0x43, 0xfa, 0x77, 0xd8, 0x5e, 0x16, 0x2d, 0x74, 0xea, 0x1a, 0xb7,
	0xab, 0x71, 0xeb, 0xb6, 0xbc, 0xf2, 0xb0, 0xdb, 0x87, 0xa6, 0x95, 0xca, 0x58, 0xae, 0xe8, 0x3b,
	0xd8, 0x1b, 0x66, 0xa3, 0x84, 0x85, 0x38, 0xe3, 0xc9, 0x74, 0xdd, 0xf0, 0x8e, 0xb7, 0xe9, 0xec,
	0xbe, 0x87, 0x5a, 0xc0, 0x22, 0x4a, 0xa0, 0xf6, 0x09, 0x57, 0x6b, 0x4d, 0xd4, 0x23, 0x3d, 0x82,
	0xc6, 0x92, 0x25, 0x79, 0xa1, 0x71, 0xcb, 0x2b, 0x8c, 0xee, 0x3b, 0xa8, 0x07, 0x2c, 0xca, 0xe8,
	0x2b, 0xa8, 0x4b, 0x16, 0x65, 0x9d, 0xca, 0x49, 0xed, 0xb4, 0x7d, 0xbe, 0xa3, 0x6b, 0x09, 0x58,
	0xe4, 0x69, 0x6f, 0xef, 0x03, 0xb4, 0xdc, 0x05, 0x0a, 0x26, 0x95, 0xe2, 0xdb, 0x50, 0xbb, 0xb2,
	0x02, 0xb2, 0x45, 0x77, 0xa0, 0x3e, 0x72, 0xfd, 0x80, 0x54, 0x28, 0x40, 0xd3, 0xb4, 0x6c, 0x2b,
	0xb0, 0x48, 0x55, 0x3d, 0xdf, 0x8d, 0x4c, 0x23, 0xb0, 0x48, 0xad, 0xf7, 0x73, 0x15, 0xf6, 0x37,
	0x37, 0x88, 0xb6, 0x61, 0xfb, 0xce, 0xb9, 0x71, 0xdc, 0x8f, 0x0e, 0xd9, 0xa2, 0xbb, 0xb0, 0x33,
	0xf0, 0x2c, 0x23, 0x18, 0x3a, 0x57, 0xa4, 0xa2, 0x8e, 0xb4, 0x65, 0x99, 0xa4, 0x4a, 0x9f, 0xc1,
	0x5e, 0x61, 0xdc, 0x5f, 0x1a, 0x43, 0xdb, 0x32, 0x49, 0x4d, 0xa1, 0x75, 0x16, 0x85, 0xae, 0x2b,
	0x40, 0x91, 0xb3, 0x04, 0x34, 0x14, 0x41, 0xe1, 0x32, 0x49, 0x53, 0xa1, 0x75, 0x1d, 0x0a, 0xbd,
	0xad, 0xd0, 0x45, 0x55, 0x25, 0x7a, 0x47, 0x57, 0xa2, 0x5d, 0x26, 0x69, 0x51, 0x02, 0xbb, 0x23,
	0xcf, 0x1d, 0x0f, 0xfd, 0xa1, 0xeb, 0xa8, 0x08, 0xa0, 0x07, 0xd0, 0xfe, 0xec, 0xb1, 0x4c, 0xd2,
	0xa6, 0x47, 0x40, 0x3e, 0x3b, 0x4a, 0x96, 0x5d, 0x4a, 0x61, 0xdf, 0xb4, 0x36, 0x42, 0xf7, 0x8a,
	0xd2, 0x1e, 0x07, 0xef, 0xd3, 0x63, 0xa0, 0x8f, 0x5c, 0x65, 0xf8, 0x41, 0x11, 0xae, 0xbb, 0x18,
	0x59, 0x8e, 0xa9, 0xc2, 0x49, 0xef, 0x12, 0x9e, 0x5f, 0xc7, 0xd1, 0xcc, 0x58, 0xb2, 0x38, 0x61,
	0x93, 0x38, 0x89, 0xe5, 0xaa, 0xd0, 0xee, 0x08, 0xc8, 0x5a, 0xbb, 0xfb, 0x6b, 0xe3, 0xde, 0x0f,
	0x94, 0xc8, 0x5b, 0x4a, 0x70, 0x3f, 0x30, 0x2e, 0x6c, 0xab, 0x90, 0xb0, 0xe4, 0xa9, 0xf6, 0x22,
	0x68, 0x3f, 0xba, 0x43, 0x4a, 0x10, 0xc7, 0x0d, 0x4a, 0xe9, 0x9b, 0x50, 0x75, 0x6f, 0x8a, 0x88,
	0x8f, 0x86, 0xa7, 0x0b, 0xaf, 0x16, 0xf3, 0x18, 0x06, 0xc3, 0x81, 0x61, 0x93, 0x9a, 0x3a, 0xba,
	0x1d, 0xfa, 0x7e, 0x21, 0xb7, 0x16, 0xff, 0xca, 0x33, 0x4c, 0xad, 0x74, 0xc1, 0x75, 0xe9, 0xde,
	0x39, 0x26, 0x69, 0xf6, 0x66, 0x00, 0x83, 0x24, 0xc6, 0x54, 0x06, 0xab, 0x05, 0x2a, 0x29, 0x07,
	0xae, 0x13, 0x78, 0xae, 0x3d, 0xb2, 0x0d, 0x47, 0x55, 0x48, 0x61, 0xdf, 0xfa, 0x26, 0xb0, 0x3c,
	0xc7, 0xb0, 0x07, 0xf6, 0xd0, 0x72, 0xd4, 0xca, 0xec, 0x40, 0xdd, 0x71, 0x4d, 0xb5, 0x30, 0x2d,
	0x68, 0x18, 0xe6, 0xed, 0xd0, 0x21, 0x35, 0xba, 0x07, 0xad, 0x0b, 0xc3, 0xb3, 0x6e, 0xad, 0xc0,
	0xb0, 0x49, 0x5d, 0x31, 0xd9, 0xae, 0x61, 0x5e, 0x18, 0xb6, 0xe1, 0x0c, 0x2c, 0x8f, 0x34, 0x7a,
	0xe7, 0x40, 0x8d, 0x5c, 0xce, 0x30, 0x95, 0x71, 0xa8, 0xb7, 0x51, 0x67, 0xdc, 0x07, 0xf0, 0x2d,
	0xfb, 0xd2, 0x1f, 0x5e, 0x29, 0xb1, 0x8b, 0xb5, 0x32, 0xd6, 0x56, 0xa5, 0xf7, 0x43, 0x03, 0x76,
	0xf5, 0x12, 0x4e, 0x51, 0x68, 0xf8, 0x01, 0xb4, 0x8d, 0x74, 0x55, 0xba, 0x8a, 0xfa, 0xc6, 0xb1,
	0x90, 0x39, 0x4b, 0x6e, 0x59, 0x38, 0x8b, 0x53, 0x24, 0x15, 0xfa, 0x12, 0x8e, 0x37, 0x7d, 0x7e,
	0xc8, 0x12, 0xf4, 0x51, 0x92, 0xaa, 0xae, 0x8b, 0xb3, 0xe9, 0x05, 0x4b, 0x58, 0x1a, 0xa2, 0x20,
	0xb5, 0x47, 0x0c, 0x0e, 0xca, 0xef, 0xb8, 0xf8, 0x44, 0xea, 0xf4, 0x10, 0x0e, 0xd6, 0xbe, 0x6b,
	0x26, 0xa6, 0x66, 0x9c, 0x7d, 0x22, 0x0d, 0x15, 0x7a, 0xc5, 0x92, 0x04, 0xc5, 0x6a, 0x38, 0x67,
	0x11, 0x92, 0x26, 0x7d, 0x01, 0x87, 0x9b, 0x89, 0x8a, 0x83, 0x6d, 0x35, 0xed, 0x35, 0xd9, 0x30,
	0x95, 0x28, 0x1e, 0x58, 0x88, 0x64, 0x47, 0x15, 0x3f, 0x40, 0x21, 0xe3, 0x07, 0x25, 0x00, 0x92,
	0x96, 0xba, 0x8e, 0x37, 0xb8, 0x22, 0xa0, 0xf7, 0x00, 0x43, 0x81, 0x92, 0xb4, 0x95, 0x02, 0x37,
	0xb8, 0x1a, 0xb3, 0x3c, 0x91, 0x64, 0x57, 0x59, 0xc3, 0x29, 0xea, 0xb7, 0x08, 0xd9, 0x53, 0xca,
	0x7b, 0x3c, 0x41, 0xb2, 0xaf, 0xaa, 0x56, 0x4f, 0x46, 0x96, 0xc5, 0x51, 0x3a, 0xc7, 0x54, 0x92,
	0x03, 0xa5, 0xe5, 0x4d, 0x3e, 0x41, 0x91, 0xa2, 0xc4, 0x8c, 0x10, 0x7d, 0x29, 0x93, 0x3c, 0x93,
	0x28, 0xc8, 0x33, 0x3d, 0x5a, 0x9e, 0x4a, 0xc1, 0x93, 0x51, 0xc2, 0x52, 0x24, 0x54, 0x0d, 0xef,
	0x4a, 0xf0, 0x7c, 0x41, 0x0e, 0xf5, 0x44, 0xf9, 0x14, 0xc9, 0x91, 0xca, 0x67, 0xf3, 0x62, 0x3e,
	0xe4, 0xb9, 0xea, 0xc3, 0x97, 0x5c, 0xb0, 0x08, 0x55, 0x2c, 0x8b, 0x53, 0x14, 0xe4, 0x58, 0xf5,
	0xb1, 0xf6, 0x5e, 0xc6, 0x09, 0x92, 0x17, 0x8f, 0x60, 0x66, 0x2c, 0x30, 0x94, 0x5c, 0xac, 0x48,
	0x47, 0x65, 0xf4, 0xf3, 0x49, 0xf1, 0xaf, 0xa9, 0xe8, 0xfe, 0xa4, 0x0a, 0x1a, 0xc7, 0x8b, 0x11,
	0xe7, 0x09, 0x79, 0xa9, 0x57, 0x94, 0x85, 0xda, 0xf8, 0xb3, 0xa2, 0xb4, 0x64, 0x38, 0x2d, 0xcb,
	0x7d, 0xa5, 0x7a, 0x51, 0x0e, 0x1f, 0xc5, 0x12, 0x05, 0x79, 0xad, 0x52, 0x5c, 0x30, 0x81, 0xb7,
	0x28, 0xbf, 0x4c, 0xfa, 0x2f, 0xf4, 0x39, 0x3c, 0x1b, 0x08, 0xd4, 0xfa, 0xb0, 0xe4, 0x96, 0xa7,
	0xb1, 0xe4, 0x82, 0xfc, 0x55, 0x51, 0xdb, 0x3c, 0x8a, 0xe2, 0x34, 0x22, 0x27, 0xaa, 0x23, 0x0f,
	0x43, 0xbe, 0x44, 0xb1, 0x22, 0x6f, 0x54, 0xd3, 0x26, 0x4e, 0xf2, 0x88, 0x74, 0xd5, 0x55, 0xff,
	0x4c, 0x79, 0xcd, 0x33, 0x49, 0xde, 0x2a, 0x55, 0x37, 0x77, 0x94, 0xbc, 0xeb, 0x79, 0xd0, 0xd6,
	0x63, 0xf5, 0x79, 0x2e, 0x42, 0x2c, 0x16, 0x7b, 0x60, 0xd8, 0xf7, 0xbe, 0x7b, 0xe7, 0x0d, 0xd4,
	0x15, 0x51, 0x2b, 0x7c, 0xe9, 0x97, 0x76, 0x45, 0xf5, 0x72, 0x1d, 0x04, 0xa3, 0xd2, 0xa1, 0x77,
	0x6e, 0x60, 0xbb, 0x8e, 0x55, 0x7a, 0x6a, 0xbd, 0xf7, 0x70, 0x38, 0x48, 0x78, 0x3e, 0x1d, 0xa6,
	0xb1, 0x34, 0x99, 0x64, 0x6b, 0x6e, 0x75, 0x9d, 0xbe, 0xcf, 0x05, 0x92, 0x2d, 0xd5, 0x82, 0xc3,
	0x35, 0x86, 0x54, 0x7a, 0x5d, 0x20, 0xd7, 0xab, 0x05, 0x8a, 0xf1, 0x15, 0xa6, 0xe5, 0xab, 0xbc,
	0x09, 0xd5, 0xf1, 0x3f, 0x8a, 0x97, 0xc1, 0xf8, 0x9c, 0x54, 0xfe, 0xf7, 0x7f, 0x68, 0x65, 0x98,
	0x66, 0xb1, 0x8c, 0x97, 0x48, 0x5f, 0xf7, 0x8b, 0xcf, 0x97, 0x7e, 0xf9, 0xf9, 0xd2, 0xbf, 0x8c,
	0x31, 0x99, 0xba, 0x7a, 0x10, 0x59, 0xe7, 0xd7, 0x9f, 0x6a, 0xfa, 0xff, 0xe7, 0x4b, 0xc4, 0xc5,
	0xdf, 0xbe, 0x7d, 0x1b, 0xc5, 0x72, 0x96, 0x4f, 0xfa, 0x21, 0x9f, 0x9f, 0xcd, 0xe3, 0x50, 0xf0,
	0x8c, 0x3f, 0xc8, 0xb3, 0x39, 0x0f, 0xcf, 0xc4, 0x22, 0x3c, 0x2b, 0xbe, 0x90, 0x26, 0x4d, 0x4d,
	0xf8, 0xcf, 0xdf, 0x02, 0x00, 0x00, 0xff, 0xff, 0xcd, 0x21, 0x5d, 0xad, 0x3d, 0x09, 0x00, 0x00,
}
