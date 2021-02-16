// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_baremetalmachine.proto

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

type BareMetalMachinePowerState int32

const (
	BareMetalMachinePowerState_Unknown BareMetalMachinePowerState = 0
	BareMetalMachinePowerState_Running BareMetalMachinePowerState = 1
	BareMetalMachinePowerState_Off     BareMetalMachinePowerState = 2
)

var BareMetalMachinePowerState_name = map[int32]string{
	0: "Unknown",
	1: "Running",
	2: "Off",
}

var BareMetalMachinePowerState_value = map[string]int32{
	"Unknown": 0,
	"Running": 1,
	"Off":     2,
}

func (x BareMetalMachinePowerState) String() string {
	return proto.EnumName(BareMetalMachinePowerState_name, int32(x))
}

func (BareMetalMachinePowerState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{0}
}

type BareMetalMachineRequest struct {
	BareMetalMachines    []*BareMetalMachine `protobuf:"bytes,1,rep,name=BareMetalMachines,proto3" json:"BareMetalMachines,omitempty"`
	OperationType        common.Operation    `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *BareMetalMachineRequest) Reset()         { *m = BareMetalMachineRequest{} }
func (m *BareMetalMachineRequest) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachineRequest) ProtoMessage()    {}
func (*BareMetalMachineRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{0}
}

func (m *BareMetalMachineRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineRequest.Unmarshal(m, b)
}
func (m *BareMetalMachineRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineRequest.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineRequest.Merge(m, src)
}
func (m *BareMetalMachineRequest) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineRequest.Size(m)
}
func (m *BareMetalMachineRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineRequest.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineRequest proto.InternalMessageInfo

func (m *BareMetalMachineRequest) GetBareMetalMachines() []*BareMetalMachine {
	if m != nil {
		return m.BareMetalMachines
	}
	return nil
}

func (m *BareMetalMachineRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type BareMetalMachineResponse struct {
	BareMetalMachines    []*BareMetalMachine `protobuf:"bytes,1,rep,name=BareMetalMachines,proto3" json:"BareMetalMachines,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *BareMetalMachineResponse) Reset()         { *m = BareMetalMachineResponse{} }
func (m *BareMetalMachineResponse) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachineResponse) ProtoMessage()    {}
func (*BareMetalMachineResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{1}
}

func (m *BareMetalMachineResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineResponse.Unmarshal(m, b)
}
func (m *BareMetalMachineResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineResponse.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineResponse.Merge(m, src)
}
func (m *BareMetalMachineResponse) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineResponse.Size(m)
}
func (m *BareMetalMachineResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineResponse.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineResponse proto.InternalMessageInfo

func (m *BareMetalMachineResponse) GetBareMetalMachines() []*BareMetalMachine {
	if m != nil {
		return m.BareMetalMachines
	}
	return nil
}

func (m *BareMetalMachineResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *BareMetalMachineResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type BareMetalMachineDisk struct {
	DiskName             string   `protobuf:"bytes,1,opt,name=diskName,proto3" json:"diskName,omitempty"`
	DiskSizeGB           int32    `protobuf:"varint,2,opt,name=diskSizeGB,proto3" json:"diskSizeGB,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BareMetalMachineDisk) Reset()         { *m = BareMetalMachineDisk{} }
func (m *BareMetalMachineDisk) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachineDisk) ProtoMessage()    {}
func (*BareMetalMachineDisk) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{2}
}

func (m *BareMetalMachineDisk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineDisk.Unmarshal(m, b)
}
func (m *BareMetalMachineDisk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineDisk.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineDisk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineDisk.Merge(m, src)
}
func (m *BareMetalMachineDisk) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineDisk.Size(m)
}
func (m *BareMetalMachineDisk) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineDisk.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineDisk proto.InternalMessageInfo

func (m *BareMetalMachineDisk) GetDiskName() string {
	if m != nil {
		return m.DiskName
	}
	return ""
}

func (m *BareMetalMachineDisk) GetDiskSizeGB() int32 {
	if m != nil {
		return m.DiskSizeGB
	}
	return 0
}

type BareMetalMachineStorageConfiguration struct {
	Disks                []*BareMetalMachineDisk `protobuf:"bytes,1,rep,name=disks,proto3" json:"disks,omitempty"`
	ImageReference       string                  `protobuf:"bytes,2,opt,name=imageReference,proto3" json:"imageReference,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                `json:"-"`
	XXX_unrecognized     []byte                  `json:"-"`
	XXX_sizecache        int32                   `json:"-"`
}

func (m *BareMetalMachineStorageConfiguration) Reset()         { *m = BareMetalMachineStorageConfiguration{} }
func (m *BareMetalMachineStorageConfiguration) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachineStorageConfiguration) ProtoMessage()    {}
func (*BareMetalMachineStorageConfiguration) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{3}
}

func (m *BareMetalMachineStorageConfiguration) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineStorageConfiguration.Unmarshal(m, b)
}
func (m *BareMetalMachineStorageConfiguration) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineStorageConfiguration.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineStorageConfiguration) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineStorageConfiguration.Merge(m, src)
}
func (m *BareMetalMachineStorageConfiguration) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineStorageConfiguration.Size(m)
}
func (m *BareMetalMachineStorageConfiguration) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineStorageConfiguration.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineStorageConfiguration proto.InternalMessageInfo

func (m *BareMetalMachineStorageConfiguration) GetDisks() []*BareMetalMachineDisk {
	if m != nil {
		return m.Disks
	}
	return nil
}

func (m *BareMetalMachineStorageConfiguration) GetImageReference() string {
	if m != nil {
		return m.ImageReference
	}
	return ""
}

type BareMetalMachineOperatingSystemConfiguration struct {
	ComputerName         string               `protobuf:"bytes,1,opt,name=computerName,proto3" json:"computerName,omitempty"`
	Administrator        *UserConfiguration   `protobuf:"bytes,2,opt,name=administrator,proto3" json:"administrator,omitempty"`
	Users                []*UserConfiguration `protobuf:"bytes,3,rep,name=users,proto3" json:"users,omitempty"`
	CustomData           string               `protobuf:"bytes,4,opt,name=customData,proto3" json:"customData,omitempty"`
	Publickeys           []*SSHPublicKey      `protobuf:"bytes,5,rep,name=publickeys,proto3" json:"publickeys,omitempty"`
	LinuxConfiguration   *LinuxConfiguration  `protobuf:"bytes,6,opt,name=linuxConfiguration,proto3" json:"linuxConfiguration,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *BareMetalMachineOperatingSystemConfiguration) Reset() {
	*m = BareMetalMachineOperatingSystemConfiguration{}
}
func (m *BareMetalMachineOperatingSystemConfiguration) String() string {
	return proto.CompactTextString(m)
}
func (*BareMetalMachineOperatingSystemConfiguration) ProtoMessage() {}
func (*BareMetalMachineOperatingSystemConfiguration) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{4}
}

func (m *BareMetalMachineOperatingSystemConfiguration) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineOperatingSystemConfiguration.Unmarshal(m, b)
}
func (m *BareMetalMachineOperatingSystemConfiguration) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineOperatingSystemConfiguration.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineOperatingSystemConfiguration) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineOperatingSystemConfiguration.Merge(m, src)
}
func (m *BareMetalMachineOperatingSystemConfiguration) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineOperatingSystemConfiguration.Size(m)
}
func (m *BareMetalMachineOperatingSystemConfiguration) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineOperatingSystemConfiguration.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineOperatingSystemConfiguration proto.InternalMessageInfo

func (m *BareMetalMachineOperatingSystemConfiguration) GetComputerName() string {
	if m != nil {
		return m.ComputerName
	}
	return ""
}

func (m *BareMetalMachineOperatingSystemConfiguration) GetAdministrator() *UserConfiguration {
	if m != nil {
		return m.Administrator
	}
	return nil
}

func (m *BareMetalMachineOperatingSystemConfiguration) GetUsers() []*UserConfiguration {
	if m != nil {
		return m.Users
	}
	return nil
}

func (m *BareMetalMachineOperatingSystemConfiguration) GetCustomData() string {
	if m != nil {
		return m.CustomData
	}
	return ""
}

func (m *BareMetalMachineOperatingSystemConfiguration) GetPublickeys() []*SSHPublicKey {
	if m != nil {
		return m.Publickeys
	}
	return nil
}

func (m *BareMetalMachineOperatingSystemConfiguration) GetLinuxConfiguration() *LinuxConfiguration {
	if m != nil {
		return m.LinuxConfiguration
	}
	return nil
}

type BareMetalMachineNetworkInterface struct {
	NetworkInterfaceName string   `protobuf:"bytes,1,opt,name=networkInterfaceName,proto3" json:"networkInterfaceName,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BareMetalMachineNetworkInterface) Reset()         { *m = BareMetalMachineNetworkInterface{} }
func (m *BareMetalMachineNetworkInterface) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachineNetworkInterface) ProtoMessage()    {}
func (*BareMetalMachineNetworkInterface) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{5}
}

func (m *BareMetalMachineNetworkInterface) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineNetworkInterface.Unmarshal(m, b)
}
func (m *BareMetalMachineNetworkInterface) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineNetworkInterface.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineNetworkInterface) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineNetworkInterface.Merge(m, src)
}
func (m *BareMetalMachineNetworkInterface) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineNetworkInterface.Size(m)
}
func (m *BareMetalMachineNetworkInterface) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineNetworkInterface.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineNetworkInterface proto.InternalMessageInfo

func (m *BareMetalMachineNetworkInterface) GetNetworkInterfaceName() string {
	if m != nil {
		return m.NetworkInterfaceName
	}
	return ""
}

type BareMetalMachineNetworkConfiguration struct {
	Interfaces           []*BareMetalMachineNetworkInterface `protobuf:"bytes,1,rep,name=interfaces,proto3" json:"interfaces,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                            `json:"-"`
	XXX_unrecognized     []byte                              `json:"-"`
	XXX_sizecache        int32                               `json:"-"`
}

func (m *BareMetalMachineNetworkConfiguration) Reset()         { *m = BareMetalMachineNetworkConfiguration{} }
func (m *BareMetalMachineNetworkConfiguration) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachineNetworkConfiguration) ProtoMessage()    {}
func (*BareMetalMachineNetworkConfiguration) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{6}
}

func (m *BareMetalMachineNetworkConfiguration) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineNetworkConfiguration.Unmarshal(m, b)
}
func (m *BareMetalMachineNetworkConfiguration) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineNetworkConfiguration.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineNetworkConfiguration) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineNetworkConfiguration.Merge(m, src)
}
func (m *BareMetalMachineNetworkConfiguration) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineNetworkConfiguration.Size(m)
}
func (m *BareMetalMachineNetworkConfiguration) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineNetworkConfiguration.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineNetworkConfiguration proto.InternalMessageInfo

func (m *BareMetalMachineNetworkConfiguration) GetInterfaces() []*BareMetalMachineNetworkInterface {
	if m != nil {
		return m.Interfaces
	}
	return nil
}

type BareMetalMachineSize struct {
	CpuCount             int32    `protobuf:"varint,1,opt,name=cpuCount,proto3" json:"cpuCount,omitempty"`
	GpuCount             int32    `protobuf:"varint,2,opt,name=gpuCount,proto3" json:"gpuCount,omitempty"`
	MemoryMB             int32    `protobuf:"varint,3,opt,name=memoryMB,proto3" json:"memoryMB,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BareMetalMachineSize) Reset()         { *m = BareMetalMachineSize{} }
func (m *BareMetalMachineSize) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachineSize) ProtoMessage()    {}
func (*BareMetalMachineSize) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{7}
}

func (m *BareMetalMachineSize) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineSize.Unmarshal(m, b)
}
func (m *BareMetalMachineSize) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineSize.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineSize) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineSize.Merge(m, src)
}
func (m *BareMetalMachineSize) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineSize.Size(m)
}
func (m *BareMetalMachineSize) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineSize.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineSize proto.InternalMessageInfo

func (m *BareMetalMachineSize) GetCpuCount() int32 {
	if m != nil {
		return m.CpuCount
	}
	return 0
}

func (m *BareMetalMachineSize) GetGpuCount() int32 {
	if m != nil {
		return m.GpuCount
	}
	return 0
}

func (m *BareMetalMachineSize) GetMemoryMB() int32 {
	if m != nil {
		return m.MemoryMB
	}
	return 0
}

type BareMetalMachineHardwareConfiguration struct {
	MachineSize          *BareMetalMachineSize `protobuf:"bytes,1,opt,name=machineSize,proto3" json:"machineSize,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *BareMetalMachineHardwareConfiguration) Reset()         { *m = BareMetalMachineHardwareConfiguration{} }
func (m *BareMetalMachineHardwareConfiguration) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachineHardwareConfiguration) ProtoMessage()    {}
func (*BareMetalMachineHardwareConfiguration) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{8}
}

func (m *BareMetalMachineHardwareConfiguration) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachineHardwareConfiguration.Unmarshal(m, b)
}
func (m *BareMetalMachineHardwareConfiguration) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachineHardwareConfiguration.Marshal(b, m, deterministic)
}
func (m *BareMetalMachineHardwareConfiguration) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachineHardwareConfiguration.Merge(m, src)
}
func (m *BareMetalMachineHardwareConfiguration) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachineHardwareConfiguration.Size(m)
}
func (m *BareMetalMachineHardwareConfiguration) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachineHardwareConfiguration.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachineHardwareConfiguration proto.InternalMessageInfo

func (m *BareMetalMachineHardwareConfiguration) GetMachineSize() *BareMetalMachineSize {
	if m != nil {
		return m.MachineSize
	}
	return nil
}

type BareMetalMachine struct {
	Name                 string                                        `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                   string                                        `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Storage              *BareMetalMachineStorageConfiguration         `protobuf:"bytes,3,opt,name=storage,proto3" json:"storage,omitempty"`
	Os                   *BareMetalMachineOperatingSystemConfiguration `protobuf:"bytes,4,opt,name=os,proto3" json:"os,omitempty"`
	Network              *BareMetalMachineNetworkConfiguration         `protobuf:"bytes,5,opt,name=network,proto3" json:"network,omitempty"`
	Hardware             *BareMetalMachineHardwareConfiguration        `protobuf:"bytes,6,opt,name=hardware,proto3" json:"hardware,omitempty"`
	PowerState           BareMetalMachinePowerState                    `protobuf:"varint,7,opt,name=powerState,proto3,enum=moc.cloudagent.compute.BareMetalMachinePowerState" json:"powerState,omitempty"`
	Security             *SecurityConfiguration                        `protobuf:"bytes,8,opt,name=security,proto3" json:"security,omitempty"`
	NodeName             string                                        `protobuf:"bytes,9,opt,name=nodeName,proto3" json:"nodeName,omitempty"`
	GroupName            string                                        `protobuf:"bytes,10,opt,name=groupName,proto3" json:"groupName,omitempty"`
	Status               *common.Status                                `protobuf:"bytes,11,opt,name=status,proto3" json:"status,omitempty"`
	LocationName         string                                        `protobuf:"bytes,12,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Tags                 *common.Tags                                  `protobuf:"bytes,13,opt,name=tags,proto3" json:"tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                      `json:"-"`
	XXX_unrecognized     []byte                                        `json:"-"`
	XXX_sizecache        int32                                         `json:"-"`
}

func (m *BareMetalMachine) Reset()         { *m = BareMetalMachine{} }
func (m *BareMetalMachine) String() string { return proto.CompactTextString(m) }
func (*BareMetalMachine) ProtoMessage()    {}
func (*BareMetalMachine) Descriptor() ([]byte, []int) {
	return fileDescriptor_2eaefc18860ff022, []int{9}
}

func (m *BareMetalMachine) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BareMetalMachine.Unmarshal(m, b)
}
func (m *BareMetalMachine) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BareMetalMachine.Marshal(b, m, deterministic)
}
func (m *BareMetalMachine) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BareMetalMachine.Merge(m, src)
}
func (m *BareMetalMachine) XXX_Size() int {
	return xxx_messageInfo_BareMetalMachine.Size(m)
}
func (m *BareMetalMachine) XXX_DiscardUnknown() {
	xxx_messageInfo_BareMetalMachine.DiscardUnknown(m)
}

var xxx_messageInfo_BareMetalMachine proto.InternalMessageInfo

func (m *BareMetalMachine) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *BareMetalMachine) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *BareMetalMachine) GetStorage() *BareMetalMachineStorageConfiguration {
	if m != nil {
		return m.Storage
	}
	return nil
}

func (m *BareMetalMachine) GetOs() *BareMetalMachineOperatingSystemConfiguration {
	if m != nil {
		return m.Os
	}
	return nil
}

func (m *BareMetalMachine) GetNetwork() *BareMetalMachineNetworkConfiguration {
	if m != nil {
		return m.Network
	}
	return nil
}

func (m *BareMetalMachine) GetHardware() *BareMetalMachineHardwareConfiguration {
	if m != nil {
		return m.Hardware
	}
	return nil
}

func (m *BareMetalMachine) GetPowerState() BareMetalMachinePowerState {
	if m != nil {
		return m.PowerState
	}
	return BareMetalMachinePowerState_Unknown
}

func (m *BareMetalMachine) GetSecurity() *SecurityConfiguration {
	if m != nil {
		return m.Security
	}
	return nil
}

func (m *BareMetalMachine) GetNodeName() string {
	if m != nil {
		return m.NodeName
	}
	return ""
}

func (m *BareMetalMachine) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *BareMetalMachine) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *BareMetalMachine) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *BareMetalMachine) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func init() {
	proto.RegisterEnum("moc.cloudagent.compute.BareMetalMachinePowerState", BareMetalMachinePowerState_name, BareMetalMachinePowerState_value)
	proto.RegisterType((*BareMetalMachineRequest)(nil), "moc.cloudagent.compute.BareMetalMachineRequest")
	proto.RegisterType((*BareMetalMachineResponse)(nil), "moc.cloudagent.compute.BareMetalMachineResponse")
	proto.RegisterType((*BareMetalMachineDisk)(nil), "moc.cloudagent.compute.BareMetalMachineDisk")
	proto.RegisterType((*BareMetalMachineStorageConfiguration)(nil), "moc.cloudagent.compute.BareMetalMachineStorageConfiguration")
	proto.RegisterType((*BareMetalMachineOperatingSystemConfiguration)(nil), "moc.cloudagent.compute.BareMetalMachineOperatingSystemConfiguration")
	proto.RegisterType((*BareMetalMachineNetworkInterface)(nil), "moc.cloudagent.compute.BareMetalMachineNetworkInterface")
	proto.RegisterType((*BareMetalMachineNetworkConfiguration)(nil), "moc.cloudagent.compute.BareMetalMachineNetworkConfiguration")
	proto.RegisterType((*BareMetalMachineSize)(nil), "moc.cloudagent.compute.BareMetalMachineSize")
	proto.RegisterType((*BareMetalMachineHardwareConfiguration)(nil), "moc.cloudagent.compute.BareMetalMachineHardwareConfiguration")
	proto.RegisterType((*BareMetalMachine)(nil), "moc.cloudagent.compute.BareMetalMachine")
}

func init() {
	proto.RegisterFile("moc_cloudagent_baremetalmachine.proto", fileDescriptor_2eaefc18860ff022)
}

var fileDescriptor_2eaefc18860ff022 = []byte{
	// 941 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x56, 0xdd, 0x6e, 0x1b, 0x45,
	0x14, 0xae, 0xed, 0xd8, 0x89, 0x8f, 0x9b, 0x28, 0x8c, 0x02, 0x5d, 0x59, 0x50, 0x45, 0xdb, 0x16,
	0x85, 0xaa, 0xd8, 0x60, 0xb8, 0xe0, 0x02, 0x54, 0xe1, 0x06, 0xd1, 0x08, 0x92, 0x54, 0xe3, 0x34,
	0x82, 0xde, 0x54, 0xe3, 0xf5, 0x78, 0x33, 0x78, 0x67, 0x66, 0x99, 0x9f, 0x18, 0x73, 0xc5, 0x15,
	0x0f, 0xc0, 0x43, 0xc0, 0x4b, 0xf0, 0x20, 0x3c, 0x0e, 0xda, 0xd9, 0x5d, 0x7b, 0xbd, 0xb6, 0x91,
	0x73, 0xc1, 0x95, 0x3d, 0xe7, 0x9c, 0xef, 0x3b, 0xdf, 0x9c, 0x33, 0x67, 0x76, 0xe0, 0x09, 0x97,
	0xc1, 0xdb, 0x20, 0x92, 0x76, 0x44, 0x42, 0x2a, 0xcc, 0xdb, 0x21, 0x51, 0x94, 0x53, 0x43, 0x22,
	0x4e, 0x82, 0x1b, 0x26, 0x68, 0x27, 0x56, 0xd2, 0x48, 0xf4, 0x1e, 0x97, 0x41, 0x67, 0x11, 0xd6,
	0x09, 0x24, 0x8f, 0xad, 0xa1, 0xed, 0x87, 0xa1, 0x94, 0x61, 0x44, 0xbb, 0x2e, 0x6a, 0x68, 0xc7,
	0xdd, 0xa9, 0x22, 0x71, 0x4c, 0x95, 0x4e, 0x71, 0xed, 0x07, 0x8e, 0x5e, 0x72, 0x2e, 0x45, 0xf6,
	0x93, 0x39, 0x1e, 0x95, 0xf2, 0xde, 0x32, 0x65, 0x6c, 0x29, 0xab, 0xff, 0x57, 0x05, 0x1e, 0xf4,
	0x89, 0xa2, 0xe7, 0x89, 0xa0, 0xf3, 0xd4, 0x85, 0xe9, 0xcf, 0x96, 0x6a, 0x83, 0xae, 0xe1, 0x9d,
	0xb2, 0x4b, 0x7b, 0x95, 0xe3, 0xda, 0x49, 0xab, 0x77, 0xd2, 0x59, 0xaf, 0xb6, 0xb3, 0xc2, 0xb5,
	0x4a, 0x81, 0x3e, 0x87, 0xfd, 0xcb, 0x98, 0x2a, 0x62, 0x98, 0x14, 0x57, 0xb3, 0x98, 0x7a, 0xd5,
	0xe3, 0xca, 0xc9, 0x41, 0xef, 0xc0, 0x71, 0xce, 0x3d, 0x78, 0x39, 0xc8, 0xff, 0xbb, 0x02, 0xde,
	0xaa, 0x52, 0x1d, 0x4b, 0xa1, 0xe9, 0xff, 0x26, 0xb5, 0x07, 0x0d, 0x4c, 0xb5, 0x8d, 0x8c, 0xd3,
	0xd8, 0xea, 0xb5, 0x3b, 0x69, 0x37, 0x3a, 0x79, 0x37, 0x3a, 0x7d, 0x29, 0xa3, 0x6b, 0x12, 0x59,
	0x8a, 0xb3, 0x48, 0x74, 0x04, 0xf5, 0x6f, 0x94, 0x92, 0xca, 0xab, 0x1d, 0x57, 0x4e, 0x9a, 0x38,
	0x5d, 0xf8, 0x18, 0x8e, 0xca, 0xf4, 0xa7, 0x4c, 0x4f, 0x50, 0x1b, 0xf6, 0x46, 0x4c, 0x4f, 0x2e,
	0x08, 0xa7, 0x5e, 0xc5, 0x01, 0xe6, 0x6b, 0xf4, 0x10, 0x20, 0xf9, 0x3f, 0x60, 0xbf, 0xd2, 0x6f,
	0xfb, 0x4e, 0x41, 0x1d, 0x17, 0x2c, 0xfe, 0x1f, 0x15, 0x78, 0x5c, 0x26, 0x1d, 0x18, 0xa9, 0x48,
	0x48, 0x5f, 0x48, 0x31, 0x66, 0xa1, 0x4d, 0xeb, 0x87, 0xfa, 0x50, 0x4f, 0x60, 0x79, 0x49, 0x9e,
	0x6d, 0x5b, 0x92, 0x44, 0x21, 0x4e, 0xa1, 0xe8, 0x43, 0x38, 0x60, 0x9c, 0x84, 0x14, 0xd3, 0x31,
	0x55, 0x54, 0x04, 0x69, 0xdb, 0x9a, 0xb8, 0x64, 0xf5, 0xff, 0xac, 0xc1, 0xb3, 0x32, 0x4f, 0xd6,
	0x49, 0x11, 0x0e, 0x66, 0xda, 0x50, 0xbe, 0x2c, 0xce, 0x87, 0xfb, 0x59, 0x7e, 0x55, 0xa8, 0xc2,
	0x92, 0x0d, 0x5d, 0xc2, 0x3e, 0x19, 0x71, 0x26, 0x98, 0x36, 0x8a, 0x18, 0xa9, 0xb2, 0x76, 0x7c,
	0xb4, 0x69, 0x23, 0xaf, 0x35, 0x55, 0x4b, 0x59, 0xf0, 0x32, 0x1e, 0x3d, 0x87, 0xba, 0xd5, 0x54,
	0x69, 0xaf, 0xe6, 0x2a, 0x72, 0x07, 0xa2, 0x14, 0x97, 0xf4, 0x26, 0xb0, 0xda, 0x48, 0x7e, 0x4a,
	0x0c, 0xf1, 0x76, 0x9c, 0xe6, 0x82, 0x05, 0x9d, 0x02, 0xc4, 0x76, 0x18, 0xb1, 0x60, 0x42, 0x67,
	0xda, 0xab, 0xbb, 0x2c, 0x8f, 0x37, 0x65, 0x19, 0x0c, 0x5e, 0xbe, 0x72, 0xc1, 0xdf, 0xd1, 0x19,
	0x2e, 0xe0, 0xd0, 0x1b, 0x40, 0x11, 0x13, 0xf6, 0x97, 0x25, 0x09, 0x5e, 0xc3, 0x6d, 0xfe, 0xe9,
	0x26, 0xb6, 0xef, 0x57, 0x10, 0x78, 0x0d, 0x8b, 0x7f, 0x0d, 0xc7, 0xe5, 0x3e, 0x5d, 0x50, 0x33,
	0x95, 0x6a, 0x72, 0x26, 0x0c, 0x55, 0x63, 0x12, 0x50, 0xd4, 0x83, 0x23, 0x51, 0xb2, 0x15, 0x7a,
	0xb4, 0xd6, 0xe7, 0xff, 0xb6, 0xe6, 0x54, 0x66, 0xc4, 0xcb, 0x8d, 0xff, 0x01, 0x80, 0xe5, 0xc8,
	0xfc, 0x68, 0x7e, 0xb1, 0xed, 0xd1, 0x2c, 0x4b, 0xc5, 0x05, 0x2e, 0xff, 0xa7, 0xd5, 0x61, 0x4b,
	0x46, 0x26, 0x19, 0xb6, 0x20, 0xb6, 0x2f, 0xa4, 0x15, 0xc6, 0x6d, 0xa1, 0x8e, 0xe7, 0xeb, 0xc4,
	0x17, 0xe6, 0xbe, 0x74, 0xd4, 0xe6, 0xeb, 0xc4, 0xc7, 0x29, 0x97, 0x6a, 0x76, 0xde, 0x77, 0x53,
	0x5d, 0xc7, 0xf3, 0xb5, 0x3f, 0x85, 0x27, 0xe5, 0x5c, 0x2f, 0x89, 0x1a, 0x4d, 0x89, 0x2a, 0x0d,
	0xe1, 0x05, 0xb4, 0xf8, 0x42, 0x8b, 0xcb, 0x7f, 0x87, 0x51, 0x4c, 0x30, 0xb8, 0x48, 0xe0, 0xff,
	0x53, 0x87, 0xc3, 0x72, 0x14, 0x42, 0xb0, 0x23, 0x16, 0x0d, 0x72, 0xff, 0xd1, 0x01, 0x54, 0xd9,
	0x28, 0x9b, 0xd6, 0x2a, 0x1b, 0xa1, 0x6b, 0xd8, 0xd5, 0xe9, 0x2d, 0xe1, 0x36, 0xd3, 0xea, 0x7d,
	0xb9, 0xb5, 0x88, 0x35, 0x97, 0x0b, 0xce, 0xc9, 0xd0, 0x15, 0x54, 0xa5, 0x76, 0xa3, 0xd0, 0xea,
	0x9d, 0x6e, 0x4b, 0xf9, 0x5f, 0x57, 0x03, 0xae, 0x4a, 0x9d, 0xa8, 0xcd, 0x8e, 0x99, 0x57, 0xbf,
	0x9b, 0xda, 0x75, 0x87, 0x0e, 0xe7, 0x64, 0xe8, 0x47, 0xd8, 0xbb, 0xc9, 0xfa, 0x94, 0x0d, 0xd4,
	0x57, 0xdb, 0x12, 0xaf, 0xed, 0x2f, 0x9e, 0xd3, 0x21, 0x0c, 0x10, 0xcb, 0x29, 0x55, 0x03, 0x43,
	0x0c, 0xf5, 0x76, 0xdd, 0xd7, 0xad, 0xb7, 0x2d, 0xf9, 0xab, 0x39, 0x12, 0x17, 0x58, 0xd0, 0x19,
	0xec, 0x69, 0x1a, 0x58, 0xc5, 0xcc, 0xcc, 0xdb, 0x73, 0x72, 0x3f, 0xde, 0x78, 0x9b, 0x64, 0x71,
	0x25, 0x79, 0x39, 0x3c, 0x39, 0xcd, 0x42, 0x8e, 0xd2, 0x41, 0x6e, 0xa6, 0x9f, 0x9c, 0x7c, 0x8d,
	0xde, 0x87, 0x66, 0xa8, 0xa4, 0x8d, 0x9d, 0x13, 0x9c, 0x73, 0x61, 0x40, 0x8f, 0xa0, 0xa1, 0x0d,
	0x31, 0x56, 0x7b, 0x2d, 0x27, 0xa1, 0xe5, 0x24, 0x0c, 0x9c, 0x09, 0x67, 0xae, 0xe4, 0x3e, 0x8f,
	0x64, 0xe0, 0x92, 0x3a, 0x96, 0xfb, 0xe9, 0x7d, 0x5e, 0xb4, 0xa1, 0x0f, 0x60, 0xc7, 0x90, 0x50,
	0x7b, 0xfb, 0x8e, 0xa6, 0xe9, 0x68, 0xae, 0x48, 0xa8, 0xb1, 0x33, 0x3f, 0x7d, 0x0e, 0xed, 0xcd,
	0x65, 0x41, 0x2d, 0xd8, 0x7d, 0x2d, 0x26, 0x42, 0x4e, 0xc5, 0xe1, 0xbd, 0x64, 0x81, 0xad, 0x10,
	0x4c, 0x84, 0x87, 0x15, 0xb4, 0x0b, 0xb5, 0xcb, 0xf1, 0xf8, 0xb0, 0xda, 0xfb, 0xbd, 0x02, 0xef,
	0x96, 0x19, 0xbe, 0x4e, 0x8a, 0x84, 0x38, 0x34, 0xce, 0xc4, 0xad, 0x9c, 0x50, 0xd4, 0xdd, 0xfa,
	0x61, 0x90, 0xbe, 0x87, 0xda, 0x9f, 0x6c, 0x0f, 0x48, 0x9f, 0x25, 0xfe, 0xbd, 0xfe, 0xa7, 0x6f,
	0xba, 0x21, 0x33, 0x37, 0x76, 0x98, 0x04, 0x77, 0x39, 0x0b, 0x94, 0xd4, 0x72, 0x6c, 0xba, 0x5c,
	0x06, 0x5d, 0x15, 0x07, 0xdd, 0x05, 0x5b, 0x37, 0x63, 0x1b, 0x36, 0xdc, 0xdb, 0xe2, 0xb3, 0x7f,
	0x03, 0x00, 0x00, 0xff, 0xff, 0xcd, 0xdf, 0x0b, 0x5b, 0x38, 0x0a, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// BareMetalMachineAgentClient is the client API for BareMetalMachineAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type BareMetalMachineAgentClient interface {
	Invoke(ctx context.Context, in *BareMetalMachineRequest, opts ...grpc.CallOption) (*BareMetalMachineResponse, error)
}

type bareMetalMachineAgentClient struct {
	cc *grpc.ClientConn
}

func NewBareMetalMachineAgentClient(cc *grpc.ClientConn) BareMetalMachineAgentClient {
	return &bareMetalMachineAgentClient{cc}
}

func (c *bareMetalMachineAgentClient) Invoke(ctx context.Context, in *BareMetalMachineRequest, opts ...grpc.CallOption) (*BareMetalMachineResponse, error) {
	out := new(BareMetalMachineResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.compute.BareMetalMachineAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BareMetalMachineAgentServer is the server API for BareMetalMachineAgent service.
type BareMetalMachineAgentServer interface {
	Invoke(context.Context, *BareMetalMachineRequest) (*BareMetalMachineResponse, error)
}

// UnimplementedBareMetalMachineAgentServer can be embedded to have forward compatible implementations.
type UnimplementedBareMetalMachineAgentServer struct {
}

func (*UnimplementedBareMetalMachineAgentServer) Invoke(ctx context.Context, req *BareMetalMachineRequest) (*BareMetalMachineResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}

func RegisterBareMetalMachineAgentServer(s *grpc.Server, srv BareMetalMachineAgentServer) {
	s.RegisterService(&_BareMetalMachineAgent_serviceDesc, srv)
}

func _BareMetalMachineAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BareMetalMachineRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BareMetalMachineAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.compute.BareMetalMachineAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BareMetalMachineAgentServer).Invoke(ctx, req.(*BareMetalMachineRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _BareMetalMachineAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.compute.BareMetalMachineAgent",
	HandlerType: (*BareMetalMachineAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _BareMetalMachineAgent_Invoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_baremetalmachine.proto",
}
