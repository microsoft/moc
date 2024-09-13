// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_loadbalancer.proto

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

type LoadBalancerRequest struct {
	LoadBalancers        []*LoadBalancer  `protobuf:"bytes,1,rep,name=LoadBalancers,proto3" json:"LoadBalancers,omitempty"`
	OperationType        common.Operation `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *LoadBalancerRequest) Reset()         { *m = LoadBalancerRequest{} }
func (m *LoadBalancerRequest) String() string { return proto.CompactTextString(m) }
func (*LoadBalancerRequest) ProtoMessage()    {}
func (*LoadBalancerRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{0}
}

func (m *LoadBalancerRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadBalancerRequest.Unmarshal(m, b)
}
func (m *LoadBalancerRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadBalancerRequest.Marshal(b, m, deterministic)
}
func (m *LoadBalancerRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadBalancerRequest.Merge(m, src)
}
func (m *LoadBalancerRequest) XXX_Size() int {
	return xxx_messageInfo_LoadBalancerRequest.Size(m)
}
func (m *LoadBalancerRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadBalancerRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LoadBalancerRequest proto.InternalMessageInfo

func (m *LoadBalancerRequest) GetLoadBalancers() []*LoadBalancer {
	if m != nil {
		return m.LoadBalancers
	}
	return nil
}

func (m *LoadBalancerRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type LoadBalancerResponse struct {
	LoadBalancers        []*LoadBalancer     `protobuf:"bytes,1,rep,name=LoadBalancers,proto3" json:"LoadBalancers,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *LoadBalancerResponse) Reset()         { *m = LoadBalancerResponse{} }
func (m *LoadBalancerResponse) String() string { return proto.CompactTextString(m) }
func (*LoadBalancerResponse) ProtoMessage()    {}
func (*LoadBalancerResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{1}
}

func (m *LoadBalancerResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadBalancerResponse.Unmarshal(m, b)
}
func (m *LoadBalancerResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadBalancerResponse.Marshal(b, m, deterministic)
}
func (m *LoadBalancerResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadBalancerResponse.Merge(m, src)
}
func (m *LoadBalancerResponse) XXX_Size() int {
	return xxx_messageInfo_LoadBalancerResponse.Size(m)
}
func (m *LoadBalancerResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadBalancerResponse.DiscardUnknown(m)
}

var xxx_messageInfo_LoadBalancerResponse proto.InternalMessageInfo

func (m *LoadBalancerResponse) GetLoadBalancers() []*LoadBalancer {
	if m != nil {
		return m.LoadBalancers
	}
	return nil
}

func (m *LoadBalancerResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *LoadBalancerResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type LoadBalancerPrecheckRequest struct {
	LoadBalancers        []*LoadBalancer `protobuf:"bytes,1,rep,name=LoadBalancers,proto3" json:"LoadBalancers,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *LoadBalancerPrecheckRequest) Reset()         { *m = LoadBalancerPrecheckRequest{} }
func (m *LoadBalancerPrecheckRequest) String() string { return proto.CompactTextString(m) }
func (*LoadBalancerPrecheckRequest) ProtoMessage()    {}
func (*LoadBalancerPrecheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{2}
}

func (m *LoadBalancerPrecheckRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadBalancerPrecheckRequest.Unmarshal(m, b)
}
func (m *LoadBalancerPrecheckRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadBalancerPrecheckRequest.Marshal(b, m, deterministic)
}
func (m *LoadBalancerPrecheckRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadBalancerPrecheckRequest.Merge(m, src)
}
func (m *LoadBalancerPrecheckRequest) XXX_Size() int {
	return xxx_messageInfo_LoadBalancerPrecheckRequest.Size(m)
}
func (m *LoadBalancerPrecheckRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadBalancerPrecheckRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LoadBalancerPrecheckRequest proto.InternalMessageInfo

func (m *LoadBalancerPrecheckRequest) GetLoadBalancers() []*LoadBalancer {
	if m != nil {
		return m.LoadBalancers
	}
	return nil
}

type LoadBalancerPrecheckResponse struct {
	// The precheck result: true if the precheck criteria is passed; otherwise, false
	Result *wrappers.BoolValue `protobuf:"bytes,1,opt,name=Result,proto3" json:"Result,omitempty"`
	// The error message if the precheck is not passed; otherwise, empty string
	Error                string   `protobuf:"bytes,2,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LoadBalancerPrecheckResponse) Reset()         { *m = LoadBalancerPrecheckResponse{} }
func (m *LoadBalancerPrecheckResponse) String() string { return proto.CompactTextString(m) }
func (*LoadBalancerPrecheckResponse) ProtoMessage()    {}
func (*LoadBalancerPrecheckResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{3}
}

func (m *LoadBalancerPrecheckResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadBalancerPrecheckResponse.Unmarshal(m, b)
}
func (m *LoadBalancerPrecheckResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadBalancerPrecheckResponse.Marshal(b, m, deterministic)
}
func (m *LoadBalancerPrecheckResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadBalancerPrecheckResponse.Merge(m, src)
}
func (m *LoadBalancerPrecheckResponse) XXX_Size() int {
	return xxx_messageInfo_LoadBalancerPrecheckResponse.Size(m)
}
func (m *LoadBalancerPrecheckResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadBalancerPrecheckResponse.DiscardUnknown(m)
}

var xxx_messageInfo_LoadBalancerPrecheckResponse proto.InternalMessageInfo

func (m *LoadBalancerPrecheckResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *LoadBalancerPrecheckResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type LoadbalancerInboundNatRule struct {
	Name                 string          `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	FrontendPort         uint32          `protobuf:"varint,2,opt,name=frontendPort,proto3" json:"frontendPort,omitempty"`
	BackendPort          uint32          `protobuf:"varint,3,opt,name=backendPort,proto3" json:"backendPort,omitempty"`
	Protocol             common.Protocol `protobuf:"varint,4,opt,name=protocol,proto3,enum=moc.Protocol" json:"protocol,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *LoadbalancerInboundNatRule) Reset()         { *m = LoadbalancerInboundNatRule{} }
func (m *LoadbalancerInboundNatRule) String() string { return proto.CompactTextString(m) }
func (*LoadbalancerInboundNatRule) ProtoMessage()    {}
func (*LoadbalancerInboundNatRule) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{4}
}

func (m *LoadbalancerInboundNatRule) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadbalancerInboundNatRule.Unmarshal(m, b)
}
func (m *LoadbalancerInboundNatRule) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadbalancerInboundNatRule.Marshal(b, m, deterministic)
}
func (m *LoadbalancerInboundNatRule) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadbalancerInboundNatRule.Merge(m, src)
}
func (m *LoadbalancerInboundNatRule) XXX_Size() int {
	return xxx_messageInfo_LoadbalancerInboundNatRule.Size(m)
}
func (m *LoadbalancerInboundNatRule) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadbalancerInboundNatRule.DiscardUnknown(m)
}

var xxx_messageInfo_LoadbalancerInboundNatRule proto.InternalMessageInfo

func (m *LoadbalancerInboundNatRule) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *LoadbalancerInboundNatRule) GetFrontendPort() uint32 {
	if m != nil {
		return m.FrontendPort
	}
	return 0
}

func (m *LoadbalancerInboundNatRule) GetBackendPort() uint32 {
	if m != nil {
		return m.BackendPort
	}
	return 0
}

func (m *LoadbalancerInboundNatRule) GetProtocol() common.Protocol {
	if m != nil {
		return m.Protocol
	}
	return common.Protocol_All
}

type LoadbalancerOutboundNatRule struct {
	Name                 string          `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	FrontendPort         uint32          `protobuf:"varint,2,opt,name=frontendPort,proto3" json:"frontendPort,omitempty"`
	BackendPort          uint32          `protobuf:"varint,3,opt,name=backendPort,proto3" json:"backendPort,omitempty"`
	Protocol             common.Protocol `protobuf:"varint,4,opt,name=protocol,proto3,enum=moc.Protocol" json:"protocol,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *LoadbalancerOutboundNatRule) Reset()         { *m = LoadbalancerOutboundNatRule{} }
func (m *LoadbalancerOutboundNatRule) String() string { return proto.CompactTextString(m) }
func (*LoadbalancerOutboundNatRule) ProtoMessage()    {}
func (*LoadbalancerOutboundNatRule) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{3}
}

func (m *LoadbalancerOutboundNatRule) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadbalancerOutboundNatRule.Unmarshal(m, b)
}
func (m *LoadbalancerOutboundNatRule) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadbalancerOutboundNatRule.Marshal(b, m, deterministic)
}
func (m *LoadbalancerOutboundNatRule) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadbalancerOutboundNatRule.Merge(m, src)
}
func (m *LoadbalancerOutboundNatRule) XXX_Size() int {
	return xxx_messageInfo_LoadbalancerOutboundNatRule.Size(m)
}
func (m *LoadbalancerOutboundNatRule) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadbalancerOutboundNatRule.DiscardUnknown(m)
}

var xxx_messageInfo_LoadbalancerOutboundNatRule proto.InternalMessageInfo

func (m *LoadbalancerOutboundNatRule) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *LoadbalancerOutboundNatRule) GetFrontendPort() uint32 {
	if m != nil {
		return m.FrontendPort
	}
	return 0
}

func (m *LoadbalancerOutboundNatRule) GetBackendPort() uint32 {
	if m != nil {
		return m.BackendPort
	}
	return 0
}

func (m *LoadbalancerOutboundNatRule) GetProtocol() common.Protocol {
	if m != nil {
		return m.Protocol
	}
	return common.Protocol_All
}

type LoadBalancingRule struct {
	FrontendPort         uint32                 `protobuf:"varint,1,opt,name=frontendPort,proto3" json:"frontendPort,omitempty"`
	BackendPort          uint32                 `protobuf:"varint,2,opt,name=backendPort,proto3" json:"backendPort,omitempty"`
	Protocol             common.Protocol        `protobuf:"varint,3,opt,name=protocol,proto3,enum=moc.Protocol" json:"protocol,omitempty"`
	ProbeRef             *common.ProbeReference `protobuf:"bytes,4,opt,name=probeRef,proto3" json:"probeRef,omitempty"`
	Name                 string                 `protobuf:"bytes,5,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *LoadBalancingRule) Reset()         { *m = LoadBalancingRule{} }
func (m *LoadBalancingRule) String() string { return proto.CompactTextString(m) }
func (*LoadBalancingRule) ProtoMessage()    {}
func (*LoadBalancingRule) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{4}
}

func (m *LoadBalancingRule) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadBalancingRule.Unmarshal(m, b)
}
func (m *LoadBalancingRule) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadBalancingRule.Marshal(b, m, deterministic)
}
func (m *LoadBalancingRule) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadBalancingRule.Merge(m, src)
}
func (m *LoadBalancingRule) XXX_Size() int {
	return xxx_messageInfo_LoadBalancingRule.Size(m)
}
func (m *LoadBalancingRule) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadBalancingRule.DiscardUnknown(m)
}

var xxx_messageInfo_LoadBalancingRule proto.InternalMessageInfo

func (m *LoadBalancingRule) GetFrontendPort() uint32 {
	if m != nil {
		return m.FrontendPort
	}
	return 0
}

func (m *LoadBalancingRule) GetBackendPort() uint32 {
	if m != nil {
		return m.BackendPort
	}
	return 0
}

func (m *LoadBalancingRule) GetProtocol() common.Protocol {
	if m != nil {
		return m.Protocol
	}
	return common.Protocol_All
}

func (m *LoadBalancingRule) GetProbeRef() *common.ProbeReference {
	if m != nil {
		return m.ProbeRef
	}
	return nil
}

func (m *LoadBalancingRule) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type Probe struct {
	Name                 string               `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	IntervalInSeconds    uint32               `protobuf:"varint,2,opt,name=intervalInSeconds,proto3" json:"intervalInSeconds,omitempty"`
	NumberOfProbes       uint32               `protobuf:"varint,3,opt,name=numberOfProbes,proto3" json:"numberOfProbes,omitempty"`
	Protocol             common.Protocol      `protobuf:"varint,4,opt,name=protocol,proto3,enum=moc.Protocol" json:"protocol,omitempty"`
	Port                 uint32               `protobuf:"varint,5,opt,name=port,proto3" json:"port,omitempty"`
	Loadbalancingrules   []*LoadBalancingRule `protobuf:"bytes,6,rep,name=loadbalancingrules,proto3" json:"loadbalancingrules,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *Probe) Reset()         { *m = Probe{} }
func (m *Probe) String() string { return proto.CompactTextString(m) }
func (*Probe) ProtoMessage()    {}
func (*Probe) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{5}
}

func (m *Probe) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Probe.Unmarshal(m, b)
}
func (m *Probe) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Probe.Marshal(b, m, deterministic)
}
func (m *Probe) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Probe.Merge(m, src)
}
func (m *Probe) XXX_Size() int {
	return xxx_messageInfo_Probe.Size(m)
}
func (m *Probe) XXX_DiscardUnknown() {
	xxx_messageInfo_Probe.DiscardUnknown(m)
}

var xxx_messageInfo_Probe proto.InternalMessageInfo

func (m *Probe) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Probe) GetIntervalInSeconds() uint32 {
	if m != nil {
		return m.IntervalInSeconds
	}
	return 0
}

func (m *Probe) GetNumberOfProbes() uint32 {
	if m != nil {
		return m.NumberOfProbes
	}
	return 0
}

func (m *Probe) GetProtocol() common.Protocol {
	if m != nil {
		return m.Protocol
	}
	return common.Protocol_All
}

func (m *Probe) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *Probe) GetLoadbalancingrules() []*LoadBalancingRule {
	if m != nil {
		return m.Loadbalancingrules
	}
	return nil
}

type FrontEndIpConfiguration struct {
	Name                 string                           `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	PrivateIPAddress     string                           `protobuf:"bytes,2,opt,name=privateIPAddress,proto3" json:"privateIPAddress,omitempty"`
	AllocationMethod     common.IPAllocationMethod        `protobuf:"varint,3,opt,name=allocationMethod,proto3,enum=moc.IPAllocationMethod" json:"allocationMethod,omitempty"`
	SubnetRef            *common.SubnetReference          `protobuf:"bytes,4,opt,name=subnetRef,proto3" json:"subnetRef,omitempty"`
	PublicIPAddress      *common.PublicIPAddressReference `protobuf:"bytes,5,opt,name=publicIPAddress,proto3" json:"publicIPAddress,omitempty"`
	InboundNatRules      []*LoadbalancerInboundNatRule    `protobuf:"bytes,6,rep,name=inboundNatRules,proto3" json:"inboundNatRules,omitempty"`
	OutboundNatRules     []*LoadbalancerOutboundNatRule   `protobuf:"bytes,7,rep,name=outboundNatRules,proto3" json:"outboundNatRules,omitempty"`
	Loadbalancingrules   []*LoadBalancingRule             `protobuf:"bytes,8,rep,name=loadbalancingrules,proto3" json:"loadbalancingrules,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                         `json:"-"`
	XXX_unrecognized     []byte                           `json:"-"`
	XXX_sizecache        int32                            `json:"-"`
}

func (m *FrontEndIpConfiguration) Reset()         { *m = FrontEndIpConfiguration{} }
func (m *FrontEndIpConfiguration) String() string { return proto.CompactTextString(m) }
func (*FrontEndIpConfiguration) ProtoMessage()    {}
func (*FrontEndIpConfiguration) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{6}
}

func (m *FrontEndIpConfiguration) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FrontEndIpConfiguration.Unmarshal(m, b)
}
func (m *FrontEndIpConfiguration) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FrontEndIpConfiguration.Marshal(b, m, deterministic)
}
func (m *FrontEndIpConfiguration) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FrontEndIpConfiguration.Merge(m, src)
}
func (m *FrontEndIpConfiguration) XXX_Size() int {
	return xxx_messageInfo_FrontEndIpConfiguration.Size(m)
}
func (m *FrontEndIpConfiguration) XXX_DiscardUnknown() {
	xxx_messageInfo_FrontEndIpConfiguration.DiscardUnknown(m)
}

var xxx_messageInfo_FrontEndIpConfiguration proto.InternalMessageInfo

func (m *FrontEndIpConfiguration) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *FrontEndIpConfiguration) GetPrivateIPAddress() string {
	if m != nil {
		return m.PrivateIPAddress
	}
	return ""
}

func (m *FrontEndIpConfiguration) GetAllocationMethod() common.IPAllocationMethod {
	if m != nil {
		return m.AllocationMethod
	}
	return common.IPAllocationMethod_Invalid
}

func (m *FrontEndIpConfiguration) GetSubnetRef() *common.SubnetReference {
	if m != nil {
		return m.SubnetRef
	}
	return nil
}

func (m *FrontEndIpConfiguration) GetPublicIPAddress() *common.PublicIPAddressReference {
	if m != nil {
		return m.PublicIPAddress
	}
	return nil
}

func (m *FrontEndIpConfiguration) GetInboundNatRules() []*LoadbalancerInboundNatRule {
	if m != nil {
		return m.InboundNatRules
	}
	return nil
}

func (m *FrontEndIpConfiguration) GetOutboundNatRules() []*LoadbalancerOutboundNatRule {
	if m != nil {
		return m.OutboundNatRules
	}
	return nil
}

func (m *FrontEndIpConfiguration) GetLoadbalancingrules() []*LoadBalancingRule {
	if m != nil {
		return m.Loadbalancingrules
	}
	return nil
}

type LoadBalancer struct {
	Name                     string                         `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id                       string                         `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	FrontendIP               string                         `protobuf:"bytes,3,opt,name=frontendIP,proto3" json:"frontendIP,omitempty"`
	Backendpoolnames         []string                       `protobuf:"bytes,4,rep,name=backendpoolnames,proto3" json:"backendpoolnames,omitempty"`
	Networkid                string                         `protobuf:"bytes,5,opt,name=networkid,proto3" json:"networkid,omitempty"`
	Loadbalancingrules       []*LoadBalancingRule           `protobuf:"bytes,6,rep,name=loadbalancingrules,proto3" json:"loadbalancingrules,omitempty"`
	Nodefqdn                 string                         `protobuf:"bytes,7,opt,name=nodefqdn,proto3" json:"nodefqdn,omitempty"`
	GroupName                string                         `protobuf:"bytes,8,opt,name=groupName,proto3" json:"groupName,omitempty"`
	LocationName             string                         `protobuf:"bytes,9,opt,name=locationName,proto3" json:"locationName,omitempty"`
	Status                   *common.Status                 `protobuf:"bytes,10,opt,name=status,proto3" json:"status,omitempty"`
	Tags                     *common.Tags                   `protobuf:"bytes,11,opt,name=tags,proto3" json:"tags,omitempty"`
	ReplicationCount         uint32                         `protobuf:"varint,12,opt,name=replicationCount,proto3" json:"replicationCount,omitempty"`
	InboundNatRules          []*LoadbalancerInboundNatRule  `protobuf:"bytes,13,rep,name=inboundNatRules,proto3" json:"inboundNatRules,omitempty"`
	OutboundNatRules         []*LoadbalancerOutboundNatRule `protobuf:"bytes,14,rep,name=outboundNatRules,proto3" json:"outboundNatRules,omitempty"`
	FrontendIpConfigurations []*FrontEndIpConfiguration     `protobuf:"bytes,15,rep,name=frontendIpConfigurations,proto3" json:"frontendIpConfigurations,omitempty"`
	Probes                   []*Probe                       `protobuf:"bytes,16,rep,name=probes,proto3" json:"probes,omitempty"`
	UseSDN                   string                         `protobuf:"bytes,17,opt,name=useSDN,proto3" json:"useSDN,omitempty"`
	ApiVersion               string                         `protobuf:"bytes,18,opt,name=apiVersion,proto3" json:"apiVersion,omitempty"`
	XXX_NoUnkeyedLiteral     struct{}                       `json:"-"`
	XXX_unrecognized         []byte                         `json:"-"`
	XXX_sizecache            int32                          `json:"-"`
}

func (m *LoadBalancer) Reset()         { *m = LoadBalancer{} }
func (m *LoadBalancer) String() string { return proto.CompactTextString(m) }
func (*LoadBalancer) ProtoMessage()    {}
func (*LoadBalancer) Descriptor() ([]byte, []int) {
	return fileDescriptor_7464476b31ac10f8, []int{7}
}

func (m *LoadBalancer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LoadBalancer.Unmarshal(m, b)
}
func (m *LoadBalancer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LoadBalancer.Marshal(b, m, deterministic)
}
func (m *LoadBalancer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LoadBalancer.Merge(m, src)
}
func (m *LoadBalancer) XXX_Size() int {
	return xxx_messageInfo_LoadBalancer.Size(m)
}
func (m *LoadBalancer) XXX_DiscardUnknown() {
	xxx_messageInfo_LoadBalancer.DiscardUnknown(m)
}

var xxx_messageInfo_LoadBalancer proto.InternalMessageInfo

func (m *LoadBalancer) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *LoadBalancer) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *LoadBalancer) GetFrontendIP() string {
	if m != nil {
		return m.FrontendIP
	}
	return ""
}

func (m *LoadBalancer) GetBackendpoolnames() []string {
	if m != nil {
		return m.Backendpoolnames
	}
	return nil
}

func (m *LoadBalancer) GetNetworkid() string {
	if m != nil {
		return m.Networkid
	}
	return ""
}

func (m *LoadBalancer) GetLoadbalancingrules() []*LoadBalancingRule {
	if m != nil {
		return m.Loadbalancingrules
	}
	return nil
}

func (m *LoadBalancer) GetNodefqdn() string {
	if m != nil {
		return m.Nodefqdn
	}
	return ""
}

func (m *LoadBalancer) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *LoadBalancer) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *LoadBalancer) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *LoadBalancer) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func (m *LoadBalancer) GetReplicationCount() uint32 {
	if m != nil {
		return m.ReplicationCount
	}
	return 0
}

func (m *LoadBalancer) GetInboundNatRules() []*LoadbalancerInboundNatRule {
	if m != nil {
		return m.InboundNatRules
	}
	return nil
}

func (m *LoadBalancer) GetOutboundNatRules() []*LoadbalancerOutboundNatRule {
	if m != nil {
		return m.OutboundNatRules
	}
	return nil
}

func (m *LoadBalancer) GetFrontendIpConfigurations() []*FrontEndIpConfiguration {
	if m != nil {
		return m.FrontendIpConfigurations
	}
	return nil
}

func (m *LoadBalancer) GetProbes() []*Probe {
	if m != nil {
		return m.Probes
	}
	return nil
}

func (m *LoadBalancer) GetUseSDN() string {
	if m != nil {
		return m.UseSDN
	}
	return ""
}

func (m *LoadBalancer) GetApiVersion() string {
	if m != nil {
		return m.ApiVersion
	}
	return ""
}

func init() {
	proto.RegisterType((*LoadBalancerRequest)(nil), "moc.cloudagent.network.LoadBalancerRequest")
	proto.RegisterType((*LoadBalancerResponse)(nil), "moc.cloudagent.network.LoadBalancerResponse")
	proto.RegisterType((*LoadBalancerPrecheckRequest)(nil), "moc.cloudagent.network.LoadBalancerPrecheckRequest")
	proto.RegisterType((*LoadBalancerPrecheckResponse)(nil), "moc.cloudagent.network.LoadBalancerPrecheckResponse")
	proto.RegisterType((*LoadbalancerInboundNatRule)(nil), "moc.cloudagent.network.LoadbalancerInboundNatRule")
	proto.RegisterType((*LoadbalancerOutboundNatRule)(nil), "moc.cloudagent.network.LoadbalancerOutboundNatRule")
	proto.RegisterType((*LoadBalancingRule)(nil), "moc.cloudagent.network.LoadBalancingRule")
	proto.RegisterType((*Probe)(nil), "moc.cloudagent.network.Probe")
	proto.RegisterType((*FrontEndIpConfiguration)(nil), "moc.cloudagent.network.FrontEndIpConfiguration")
	proto.RegisterType((*LoadBalancer)(nil), "moc.cloudagent.network.LoadBalancer")
}

func init() { proto.RegisterFile("moc_cloudagent_loadbalancer.proto", fileDescriptor_7464476b31ac10f8) }

var fileDescriptor_7464476b31ac10f8 = []byte{
	// 953 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcc, 0x56, 0xed, 0x6e, 0xe3, 0x44,
	0x14, 0xc5, 0x6d, 0x92, 0x6d, 0x6e, 0x36, 0x69, 0x3b, 0x5b, 0x6d, 0xad, 0x40, 0xab, 0x10, 0x56,
	0xa8, 0x0b, 0xab, 0x58, 0x64, 0xe1, 0x01, 0xda, 0xb2, 0xa0, 0xa0, 0xa5, 0x8d, 0xa6, 0xab, 0x95,
	0x40, 0x48, 0x95, 0x3f, 0x26, 0x5e, 0xab, 0xce, 0x8c, 0x77, 0x66, 0xdc, 0x15, 0x3c, 0x01, 0x12,
	0x0f, 0xc0, 0x6f, 0xf8, 0xcd, 0xdf, 0x7d, 0x08, 0xde, 0x85, 0x87, 0x40, 0xbe, 0x9e, 0xc4, 0x76,
	0x3e, 0xba, 0x45, 0xea, 0x4a, 0xfc, 0x8a, 0x7d, 0xee, 0x99, 0xe3, 0x93, 0x33, 0x77, 0xae, 0x0d,
	0x1f, 0x4f, 0x85, 0x7f, 0xe9, 0xc7, 0x22, 0x0d, 0xdc, 0x90, 0x71, 0x7d, 0x19, 0x0b, 0x37, 0xf0,
	0xdc, 0xd8, 0xe5, 0x3e, 0x93, 0x83, 0x44, 0x0a, 0x2d, 0xc8, 0xc3, 0xa9, 0xf0, 0x07, 0x05, 0x65,
	0xc0, 0x99, 0x7e, 0x23, 0xe4, 0x55, 0xf7, 0x30, 0x14, 0x22, 0x8c, 0x99, 0x83, 0x2c, 0x2f, 0x9d,
	0x38, 0x6f, 0xa4, 0x9b, 0x24, 0x4c, 0xaa, 0x7c, 0x5d, 0x77, 0x1f, 0xa5, 0xc5, 0x74, 0x2a, 0xb8,
	0xf9, 0x31, 0x85, 0xc3, 0x52, 0xc1, 0x88, 0x95, 0xeb, 0xfd, 0xdf, 0x2d, 0x78, 0xf0, 0x5c, 0xb8,
	0xc1, 0x89, 0xf1, 0x41, 0xd9, 0xeb, 0x94, 0x29, 0x4d, 0xbe, 0x83, 0x76, 0x19, 0x56, 0xb6, 0xd5,
	0xdb, 0x3c, 0x6a, 0x0d, 0x1f, 0x0d, 0x56, 0x1b, 0x1c, 0x54, 0x34, 0xaa, 0x4b, 0xc9, 0x97, 0xd0,
	0x3e, 0x4f, 0x98, 0x74, 0x75, 0x24, 0xf8, 0x8b, 0x9f, 0x13, 0x66, 0x6f, 0xf4, 0xac, 0xa3, 0xce,
	0xb0, 0x83, 0x5a, 0xf3, 0x0a, 0xad, 0x92, 0xfa, 0x7f, 0x59, 0xb0, 0x57, 0x75, 0xa6, 0x12, 0xc1,
	0x15, 0xbb, 0x53, 0x6b, 0x43, 0x68, 0x50, 0xa6, 0xd2, 0x58, 0xa3, 0xa7, 0xd6, 0xb0, 0x3b, 0xc8,
	0x83, 0x1e, 0xcc, 0x82, 0x1e, 0x9c, 0x08, 0x11, 0xbf, 0x74, 0xe3, 0x94, 0x51, 0xc3, 0x24, 0x7b,
	0x50, 0x7f, 0x26, 0xa5, 0x90, 0xf6, 0x66, 0xcf, 0x3a, 0x6a, 0xd2, 0xfc, 0xa6, 0xff, 0x87, 0x05,
	0xdd, 0xe7, 0xa5, 0x0d, 0x1d, 0x71, 0x4f, 0xa4, 0x3c, 0x38, 0x73, 0x35, 0x4d, 0x63, 0x46, 0x08,
	0xd4, 0xb8, 0x3b, 0x65, 0xb6, 0x85, 0x6b, 0xf0, 0x9a, 0xf4, 0xe1, 0xfe, 0x44, 0x0a, 0xae, 0x19,
	0x0f, 0xc6, 0x42, 0xe6, 0x16, 0xda, 0xb4, 0x82, 0x91, 0x1e, 0xb4, 0x3c, 0xd7, 0xbf, 0x9a, 0x51,
	0x36, 0x91, 0x52, 0x86, 0xc8, 0x63, 0xd8, 0x42, 0xb3, 0xbe, 0x88, 0xed, 0x1a, 0x06, 0xdb, 0xc6,
	0x24, 0xc6, 0x06, 0xa4, 0xf3, 0x72, 0xff, 0x4f, 0x0b, 0x3e, 0x2c, 0x7b, 0x3c, 0x4f, 0xf5, 0xff,
	0xcf, 0xe4, 0xdf, 0x16, 0xec, 0x16, 0x9b, 0x14, 0xf1, 0x10, 0xad, 0x2d, 0xda, 0xb0, 0xde, 0x6d,
	0x63, 0xe3, 0x66, 0x1b, 0x9b, 0x37, 0xda, 0x20, 0x0e, 0x52, 0x3d, 0x46, 0xd9, 0x04, 0x1d, 0xb7,
	0x86, 0x0f, 0x66, 0x54, 0x04, 0x99, 0x64, 0xdc, 0x67, 0x74, 0x4e, 0x9a, 0x87, 0x57, 0x2f, 0xc2,
	0xeb, 0xff, 0xb6, 0x01, 0x75, 0x5c, 0xb0, 0x32, 0xda, 0x27, 0xb0, 0x1b, 0x71, 0xcd, 0xe4, 0xb5,
	0x1b, 0x8f, 0xf8, 0x05, 0xf3, 0x05, 0x0f, 0x94, 0x71, 0xbd, 0x5c, 0x20, 0x9f, 0x42, 0x87, 0xa7,
	0x53, 0x8f, 0xc9, 0xf3, 0x09, 0x4a, 0x2a, 0x93, 0xf3, 0x02, 0xfa, 0x1f, 0xa2, 0xce, 0x4c, 0x25,
	0x59, 0x52, 0x75, 0x14, 0xc2, 0x6b, 0xf2, 0x03, 0x90, 0x62, 0x2e, 0x45, 0x3c, 0x94, 0x69, 0xcc,
	0x94, 0xdd, 0xc0, 0x23, 0xf6, 0xf8, 0xdd, 0x47, 0xcc, 0xec, 0x17, 0x5d, 0x21, 0xd2, 0x7f, 0x5b,
	0x83, 0xfd, 0x6f, 0xb2, 0x0d, 0x7b, 0xc6, 0x83, 0x51, 0x72, 0x2a, 0xf8, 0x24, 0x0a, 0xd3, 0xfc,
	0xc4, 0xaf, 0xcc, 0xe7, 0x33, 0xd8, 0x49, 0x64, 0x74, 0xed, 0x6a, 0x36, 0x1a, 0x1f, 0x07, 0x81,
	0x64, 0x2a, 0x8f, 0xa7, 0x49, 0x97, 0x70, 0x72, 0x0a, 0x3b, 0x6e, 0x1c, 0x0b, 0x1f, 0xd5, 0xbe,
	0x67, 0xfa, 0x95, 0x08, 0xcc, 0x0e, 0xef, 0xa3, 0xe9, 0xd1, 0xf8, 0x78, 0xa1, 0x4c, 0x97, 0x16,
	0x90, 0x21, 0x34, 0x55, 0xea, 0x71, 0xa6, 0x8b, 0x4d, 0xdf, 0xc3, 0xd5, 0x17, 0x33, 0xd4, 0xec,
	0x7a, 0x41, 0x23, 0xdf, 0xc2, 0x76, 0x92, 0x7a, 0x71, 0xe4, 0x17, 0x1e, 0xeb, 0xb8, 0xf2, 0x20,
	0x4f, 0xbd, 0x5a, 0x2b, 0x24, 0x16, 0x57, 0x91, 0x9f, 0x60, 0x3b, 0xaa, 0xcc, 0x8c, 0x59, 0xea,
	0xc3, 0x9b, 0x52, 0x5f, 0x3d, 0x6e, 0xe8, 0xa2, 0x14, 0xb9, 0x84, 0x1d, 0x51, 0x3d, 0xed, 0xca,
	0xbe, 0x87, 0xf2, 0x4f, 0x6f, 0x23, 0xbf, 0x30, 0x29, 0xe8, 0x92, 0xd8, 0x9a, 0xbe, 0xd9, 0xba,
	0x8b, 0xbe, 0xf9, 0xa7, 0x01, 0xf7, 0xcb, 0x63, 0x7b, 0x65, 0xb3, 0x74, 0x60, 0x23, 0x0a, 0x4c,
	0x7b, 0x6c, 0x44, 0x01, 0x79, 0x04, 0x30, 0x1b, 0x0e, 0xa3, 0x71, 0x3e, 0xaa, 0x4f, 0x6a, 0xbf,
	0xbe, 0xb5, 0x2d, 0x5a, 0xc2, 0xb3, 0x16, 0x33, 0xf3, 0x21, 0x11, 0x22, 0xce, 0x84, 0x94, 0x5d,
	0xeb, 0x6d, 0x66, 0x2d, 0xb6, 0x88, 0x93, 0x8f, 0xa0, 0x69, 0x7c, 0x47, 0x81, 0x39, 0xe5, 0x05,
	0xf0, 0x1e, 0xcf, 0x0d, 0xe9, 0xc1, 0x16, 0x17, 0x01, 0x9b, 0xbc, 0x0e, 0xb8, 0x7d, 0xaf, 0xf4,
	0x47, 0xe6, 0x68, 0x66, 0x2d, 0x94, 0x22, 0x4d, 0xce, 0xb2, 0x54, 0xb6, 0x72, 0x6b, 0x73, 0x20,
	0x9b, 0x9d, 0xb3, 0x46, 0x47, 0x42, 0x13, 0x09, 0x15, 0x8c, 0x7c, 0x02, 0x0d, 0xa5, 0x5d, 0x9d,
	0x2a, 0x1b, 0xb0, 0x7b, 0x5b, 0x79, 0xdf, 0x23, 0x44, 0x4d, 0x89, 0x1c, 0x40, 0x4d, 0xbb, 0xa1,
	0xb2, 0x5b, 0x48, 0x69, 0x22, 0xe5, 0x85, 0x1b, 0x2a, 0x8a, 0x70, 0x16, 0xa6, 0x64, 0x49, 0x1c,
	0xe5, 0xb2, 0xa7, 0x22, 0xe5, 0xda, 0xbe, 0x8f, 0xa3, 0x65, 0x09, 0x5f, 0xd5, 0xed, 0xed, 0xf7,
	0xdb, 0xed, 0x9d, 0xbb, 0xec, 0xf6, 0x2b, 0xb0, 0xe7, 0x5d, 0x54, 0x9d, 0x64, 0xca, 0xde, 0xc6,
	0x07, 0x39, 0xeb, 0x1e, 0xb4, 0x66, 0x02, 0xd2, 0xb5, 0x82, 0xe4, 0x2b, 0x68, 0x24, 0xf9, 0xc4,
	0xdf, 0x41, 0xe9, 0x83, 0x75, 0xd2, 0xf9, 0xbb, 0xc9, 0x90, 0xc9, 0x43, 0x68, 0xa4, 0x8a, 0x5d,
	0x7c, 0x7d, 0x66, 0xef, 0xe2, 0x86, 0x9b, 0x3b, 0x72, 0x08, 0xe0, 0x26, 0xd1, 0x4b, 0x26, 0x55,
	0x24, 0xb8, 0x4d, 0xb0, 0x56, 0x42, 0x86, 0xbf, 0x94, 0xdf, 0xbf, 0x4c, 0x1e, 0x67, 0x8f, 0x20,
	0x0c, 0x1a, 0x23, 0x7e, 0x2d, 0xae, 0x18, 0xf9, 0xfc, 0x56, 0xdf, 0x59, 0xf9, 0x67, 0x64, 0xf7,
	0xc9, 0xed, 0xc8, 0xf9, 0x97, 0x5d, 0xff, 0x83, 0x93, 0x2f, 0x7e, 0x74, 0xc2, 0x48, 0xbf, 0x4a,
	0xbd, 0x81, 0x2f, 0xa6, 0xce, 0x34, 0xf2, 0xa5, 0x50, 0x62, 0xa2, 0x9d, 0xa9, 0xf0, 0x1d, 0x99,
	0xf8, 0x4e, 0xa1, 0xe4, 0x18, 0x25, 0xaf, 0x81, 0xaf, 0xb3, 0xa7, 0xff, 0x06, 0x00, 0x00, 0xff,
	0xff, 0xa4, 0x24, 0x22, 0x2d, 0x5e, 0x0b, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// LoadBalancerAgentClient is the client API for LoadBalancerAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type LoadBalancerAgentClient interface {
	Invoke(ctx context.Context, in *LoadBalancerRequest, opts ...grpc.CallOption) (*LoadBalancerResponse, error)
	// Prechecks whether the system is able to create specified load balancers (but does not actually create them).
	Precheck(ctx context.Context, in *LoadBalancerPrecheckRequest, opts ...grpc.CallOption) (*LoadBalancerPrecheckResponse, error)
}

type loadBalancerAgentClient struct {
	cc *grpc.ClientConn
}

func NewLoadBalancerAgentClient(cc *grpc.ClientConn) LoadBalancerAgentClient {
	return &loadBalancerAgentClient{cc}
}

func (c *loadBalancerAgentClient) Invoke(ctx context.Context, in *LoadBalancerRequest, opts ...grpc.CallOption) (*LoadBalancerResponse, error) {
	out := new(LoadBalancerResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.LoadBalancerAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *loadBalancerAgentClient) Precheck(ctx context.Context, in *LoadBalancerPrecheckRequest, opts ...grpc.CallOption) (*LoadBalancerPrecheckResponse, error) {
	out := new(LoadBalancerPrecheckResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.network.LoadBalancerAgent/Precheck", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LoadBalancerAgentServer is the server API for LoadBalancerAgent service.
type LoadBalancerAgentServer interface {
	Invoke(context.Context, *LoadBalancerRequest) (*LoadBalancerResponse, error)
	// Prechecks whether the system is able to create specified load balancers (but does not actually create them).
	Precheck(context.Context, *LoadBalancerPrecheckRequest) (*LoadBalancerPrecheckResponse, error)
}

// UnimplementedLoadBalancerAgentServer can be embedded to have forward compatible implementations.
type UnimplementedLoadBalancerAgentServer struct {
}

func (*UnimplementedLoadBalancerAgentServer) Invoke(ctx context.Context, req *LoadBalancerRequest) (*LoadBalancerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}
func (*UnimplementedLoadBalancerAgentServer) Precheck(ctx context.Context, req *LoadBalancerPrecheckRequest) (*LoadBalancerPrecheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Precheck not implemented")
}

func RegisterLoadBalancerAgentServer(s *grpc.Server, srv LoadBalancerAgentServer) {
	s.RegisterService(&_LoadBalancerAgent_serviceDesc, srv)
}

func _LoadBalancerAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoadBalancerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoadBalancerAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.LoadBalancerAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoadBalancerAgentServer).Invoke(ctx, req.(*LoadBalancerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _LoadBalancerAgent_Precheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoadBalancerPrecheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LoadBalancerAgentServer).Precheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.network.LoadBalancerAgent/Precheck",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LoadBalancerAgentServer).Precheck(ctx, req.(*LoadBalancerPrecheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _LoadBalancerAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.network.LoadBalancerAgent",
	HandlerType: (*LoadBalancerAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _LoadBalancerAgent_Invoke_Handler,
		},
		{
			MethodName: "Precheck",
			Handler:    _LoadBalancerAgent_Precheck_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_loadbalancer.proto",
}
