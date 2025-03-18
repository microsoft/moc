// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_cloudagent_key.proto

package security

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

type KeyRequest struct {
	Keys                 []*Key           `protobuf:"bytes,1,rep,name=Keys,proto3" json:"Keys,omitempty"`
	OperationType        common.Operation `protobuf:"varint,2,opt,name=OperationType,proto3,enum=moc.Operation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *KeyRequest) Reset()         { *m = KeyRequest{} }
func (m *KeyRequest) String() string { return proto.CompactTextString(m) }
func (*KeyRequest) ProtoMessage()    {}
func (*KeyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1154d4ecd5d6df6, []int{0}
}

func (m *KeyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyRequest.Unmarshal(m, b)
}
func (m *KeyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyRequest.Marshal(b, m, deterministic)
}
func (m *KeyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyRequest.Merge(m, src)
}
func (m *KeyRequest) XXX_Size() int {
	return xxx_messageInfo_KeyRequest.Size(m)
}
func (m *KeyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_KeyRequest proto.InternalMessageInfo

func (m *KeyRequest) GetKeys() []*Key {
	if m != nil {
		return m.Keys
	}
	return nil
}

func (m *KeyRequest) GetOperationType() common.Operation {
	if m != nil {
		return m.OperationType
	}
	return common.Operation_GET
}

type KeyResponse struct {
	Keys                 []*Key              `protobuf:"bytes,1,rep,name=Keys,proto3" json:"Keys,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *KeyResponse) Reset()         { *m = KeyResponse{} }
func (m *KeyResponse) String() string { return proto.CompactTextString(m) }
func (*KeyResponse) ProtoMessage()    {}
func (*KeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1154d4ecd5d6df6, []int{1}
}

func (m *KeyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyResponse.Unmarshal(m, b)
}
func (m *KeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyResponse.Marshal(b, m, deterministic)
}
func (m *KeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyResponse.Merge(m, src)
}
func (m *KeyResponse) XXX_Size() int {
	return xxx_messageInfo_KeyResponse.Size(m)
}
func (m *KeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_KeyResponse proto.InternalMessageInfo

func (m *KeyResponse) GetKeys() []*Key {
	if m != nil {
		return m.Keys
	}
	return nil
}

func (m *KeyResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *KeyResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type KeyOperationRequest struct {
	Key                    *Key                           `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Data                   string                         `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
	Algorithm              common.Algorithm               `protobuf:"varint,3,opt,name=algorithm,proto3,enum=moc.Algorithm" json:"algorithm,omitempty"`
	OBSOLETE_OperationType common.KeyOperation            `protobuf:"varint,4,opt,name=OBSOLETE_OperationType,json=OBSOLETEOperationType,proto3,enum=moc.KeyOperation" json:"OBSOLETE_OperationType,omitempty"` // Deprecated: Do not use.
	SignVerifyParams       *SignVerifyParams              `protobuf:"bytes,5,opt,name=SignVerifyParams,proto3" json:"SignVerifyParams,omitempty"`
	OperationType          common.ProviderAccessOperation `protobuf:"varint,6,opt,name=OperationType,proto3,enum=moc.ProviderAccessOperation" json:"OperationType,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}                       `json:"-"`
	XXX_unrecognized       []byte                         `json:"-"`
	XXX_sizecache          int32                          `json:"-"`
}

func (m *KeyOperationRequest) Reset()         { *m = KeyOperationRequest{} }
func (m *KeyOperationRequest) String() string { return proto.CompactTextString(m) }
func (*KeyOperationRequest) ProtoMessage()    {}
func (*KeyOperationRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1154d4ecd5d6df6, []int{2}
}

func (m *KeyOperationRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyOperationRequest.Unmarshal(m, b)
}
func (m *KeyOperationRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyOperationRequest.Marshal(b, m, deterministic)
}
func (m *KeyOperationRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyOperationRequest.Merge(m, src)
}
func (m *KeyOperationRequest) XXX_Size() int {
	return xxx_messageInfo_KeyOperationRequest.Size(m)
}
func (m *KeyOperationRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyOperationRequest.DiscardUnknown(m)
}

var xxx_messageInfo_KeyOperationRequest proto.InternalMessageInfo

func (m *KeyOperationRequest) GetKey() *Key {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *KeyOperationRequest) GetData() string {
	if m != nil {
		return m.Data
	}
	return ""
}

func (m *KeyOperationRequest) GetAlgorithm() common.Algorithm {
	if m != nil {
		return m.Algorithm
	}
	return common.Algorithm_A_UNKNOWN
}

// Deprecated: Do not use.
func (m *KeyOperationRequest) GetOBSOLETE_OperationType() common.KeyOperation {
	if m != nil {
		return m.OBSOLETE_OperationType
	}
	return common.KeyOperation_ENCRYPT
}

func (m *KeyOperationRequest) GetSignVerifyParams() *SignVerifyParams {
	if m != nil {
		return m.SignVerifyParams
	}
	return nil
}

func (m *KeyOperationRequest) GetOperationType() common.ProviderAccessOperation {
	if m != nil {
		return m.OperationType
	}
	return common.ProviderAccessOperation_Unspecified
}

type KeyOperationResponse struct {
	Data                 string              `protobuf:"bytes,1,opt,name=Data,proto3" json:"Data,omitempty"`
	Result               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
	Error                string              `protobuf:"bytes,3,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *KeyOperationResponse) Reset()         { *m = KeyOperationResponse{} }
func (m *KeyOperationResponse) String() string { return proto.CompactTextString(m) }
func (*KeyOperationResponse) ProtoMessage()    {}
func (*KeyOperationResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1154d4ecd5d6df6, []int{3}
}

func (m *KeyOperationResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyOperationResponse.Unmarshal(m, b)
}
func (m *KeyOperationResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyOperationResponse.Marshal(b, m, deterministic)
}
func (m *KeyOperationResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyOperationResponse.Merge(m, src)
}
func (m *KeyOperationResponse) XXX_Size() int {
	return xxx_messageInfo_KeyOperationResponse.Size(m)
}
func (m *KeyOperationResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyOperationResponse.DiscardUnknown(m)
}

var xxx_messageInfo_KeyOperationResponse proto.InternalMessageInfo

func (m *KeyOperationResponse) GetData() string {
	if m != nil {
		return m.Data
	}
	return ""
}

func (m *KeyOperationResponse) GetResult() *wrappers.BoolValue {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *KeyOperationResponse) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type PrivateKeyWrappingInfo struct {
	WrappingKeyName      string                      `protobuf:"bytes,1,opt,name=WrappingKeyName,proto3" json:"WrappingKeyName,omitempty"`
	WrappingKeyPublic    []byte                      `protobuf:"bytes,2,opt,name=WrappingKeyPublic,proto3" json:"WrappingKeyPublic,omitempty"`
	WrappingAlgorithm    common.KeyWrappingAlgorithm `protobuf:"varint,3,opt,name=WrappingAlgorithm,proto3,enum=moc.KeyWrappingAlgorithm" json:"WrappingAlgorithm,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                    `json:"-"`
	XXX_unrecognized     []byte                      `json:"-"`
	XXX_sizecache        int32                       `json:"-"`
}

func (m *PrivateKeyWrappingInfo) Reset()         { *m = PrivateKeyWrappingInfo{} }
func (m *PrivateKeyWrappingInfo) String() string { return proto.CompactTextString(m) }
func (*PrivateKeyWrappingInfo) ProtoMessage()    {}
func (*PrivateKeyWrappingInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1154d4ecd5d6df6, []int{4}
}

func (m *PrivateKeyWrappingInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PrivateKeyWrappingInfo.Unmarshal(m, b)
}
func (m *PrivateKeyWrappingInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PrivateKeyWrappingInfo.Marshal(b, m, deterministic)
}
func (m *PrivateKeyWrappingInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PrivateKeyWrappingInfo.Merge(m, src)
}
func (m *PrivateKeyWrappingInfo) XXX_Size() int {
	return xxx_messageInfo_PrivateKeyWrappingInfo.Size(m)
}
func (m *PrivateKeyWrappingInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_PrivateKeyWrappingInfo.DiscardUnknown(m)
}

var xxx_messageInfo_PrivateKeyWrappingInfo proto.InternalMessageInfo

func (m *PrivateKeyWrappingInfo) GetWrappingKeyName() string {
	if m != nil {
		return m.WrappingKeyName
	}
	return ""
}

func (m *PrivateKeyWrappingInfo) GetWrappingKeyPublic() []byte {
	if m != nil {
		return m.WrappingKeyPublic
	}
	return nil
}

func (m *PrivateKeyWrappingInfo) GetWrappingAlgorithm() common.KeyWrappingAlgorithm {
	if m != nil {
		return m.WrappingAlgorithm
	}
	return common.KeyWrappingAlgorithm_CKM_RSA_AES_KEY_WRAP
}

type SignVerifyParams struct {
	Algorithm            common.JSONWebKeySignatureAlgorithm `protobuf:"varint,1,opt,name=algorithm,proto3,enum=moc.JSONWebKeySignatureAlgorithm" json:"algorithm,omitempty"`
	Signature            string                              `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                            `json:"-"`
	XXX_unrecognized     []byte                              `json:"-"`
	XXX_sizecache        int32                               `json:"-"`
}

func (m *SignVerifyParams) Reset()         { *m = SignVerifyParams{} }
func (m *SignVerifyParams) String() string { return proto.CompactTextString(m) }
func (*SignVerifyParams) ProtoMessage()    {}
func (*SignVerifyParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1154d4ecd5d6df6, []int{5}
}

func (m *SignVerifyParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignVerifyParams.Unmarshal(m, b)
}
func (m *SignVerifyParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignVerifyParams.Marshal(b, m, deterministic)
}
func (m *SignVerifyParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignVerifyParams.Merge(m, src)
}
func (m *SignVerifyParams) XXX_Size() int {
	return xxx_messageInfo_SignVerifyParams.Size(m)
}
func (m *SignVerifyParams) XXX_DiscardUnknown() {
	xxx_messageInfo_SignVerifyParams.DiscardUnknown(m)
}

var xxx_messageInfo_SignVerifyParams proto.InternalMessageInfo

func (m *SignVerifyParams) GetAlgorithm() common.JSONWebKeySignatureAlgorithm {
	if m != nil {
		return m.Algorithm
	}
	return common.JSONWebKeySignatureAlgorithm_RSNULL
}

func (m *SignVerifyParams) GetSignature() string {
	if m != nil {
		return m.Signature
	}
	return ""
}

type Key struct {
	Name         string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id           string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	LocationName string `protobuf:"bytes,3,opt,name=locationName,proto3" json:"locationName,omitempty"`
	// Public Key Value
	PublicKey                     []byte                     `protobuf:"bytes,4,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	Type                          common.JsonWebKeyType      `protobuf:"varint,5,opt,name=type,proto3,enum=moc.JsonWebKeyType" json:"type,omitempty"`
	VaultName                     string                     `protobuf:"bytes,6,opt,name=vaultName,proto3" json:"vaultName,omitempty"`
	GroupName                     string                     `protobuf:"bytes,7,opt,name=groupName,proto3" json:"groupName,omitempty"`
	Status                        *common.Status             `protobuf:"bytes,8,opt,name=status,proto3" json:"status,omitempty"`
	Size                          common.KeySize             `protobuf:"varint,9,opt,name=size,proto3,enum=moc.KeySize" json:"size,omitempty"`
	Curve                         common.JsonWebKeyCurveName `protobuf:"varint,10,opt,name=curve,proto3,enum=moc.JsonWebKeyCurveName" json:"curve,omitempty"`
	KeyOps                        []common.KeyOperation      `protobuf:"varint,11,rep,packed,name=keyOps,proto3,enum=moc.KeyOperation" json:"keyOps,omitempty"`
	Tags                          *common.Tags               `protobuf:"bytes,12,opt,name=tags,proto3" json:"tags,omitempty"`
	KeyRotationFrequencyInSeconds int64                      `protobuf:"varint,13,opt,name=keyRotationFrequencyInSeconds,proto3" json:"keyRotationFrequencyInSeconds,omitempty"`
	// Private Key Value and wrapping information
	PrivateKey             []byte                  `protobuf:"bytes,14,opt,name=privateKey,proto3" json:"privateKey,omitempty"`
	PrivateKeyWrappingInfo *PrivateKeyWrappingInfo `protobuf:"bytes,15,opt,name=privateKeyWrappingInfo,proto3" json:"privateKeyWrappingInfo,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}                `json:"-"`
	XXX_unrecognized       []byte                  `json:"-"`
	XXX_sizecache          int32                   `json:"-"`
}

func (m *Key) Reset()         { *m = Key{} }
func (m *Key) String() string { return proto.CompactTextString(m) }
func (*Key) ProtoMessage()    {}
func (*Key) Descriptor() ([]byte, []int) {
	return fileDescriptor_d1154d4ecd5d6df6, []int{6}
}

func (m *Key) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Key.Unmarshal(m, b)
}
func (m *Key) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Key.Marshal(b, m, deterministic)
}
func (m *Key) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Key.Merge(m, src)
}
func (m *Key) XXX_Size() int {
	return xxx_messageInfo_Key.Size(m)
}
func (m *Key) XXX_DiscardUnknown() {
	xxx_messageInfo_Key.DiscardUnknown(m)
}

var xxx_messageInfo_Key proto.InternalMessageInfo

func (m *Key) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Key) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Key) GetLocationName() string {
	if m != nil {
		return m.LocationName
	}
	return ""
}

func (m *Key) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *Key) GetType() common.JsonWebKeyType {
	if m != nil {
		return m.Type
	}
	return common.JsonWebKeyType_EC
}

func (m *Key) GetVaultName() string {
	if m != nil {
		return m.VaultName
	}
	return ""
}

func (m *Key) GetGroupName() string {
	if m != nil {
		return m.GroupName
	}
	return ""
}

func (m *Key) GetStatus() *common.Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *Key) GetSize() common.KeySize {
	if m != nil {
		return m.Size
	}
	return common.KeySize_K_UNKNOWN
}

func (m *Key) GetCurve() common.JsonWebKeyCurveName {
	if m != nil {
		return m.Curve
	}
	return common.JsonWebKeyCurveName_P_256
}

func (m *Key) GetKeyOps() []common.KeyOperation {
	if m != nil {
		return m.KeyOps
	}
	return nil
}

func (m *Key) GetTags() *common.Tags {
	if m != nil {
		return m.Tags
	}
	return nil
}

func (m *Key) GetKeyRotationFrequencyInSeconds() int64 {
	if m != nil {
		return m.KeyRotationFrequencyInSeconds
	}
	return 0
}

func (m *Key) GetPrivateKey() []byte {
	if m != nil {
		return m.PrivateKey
	}
	return nil
}

func (m *Key) GetPrivateKeyWrappingInfo() *PrivateKeyWrappingInfo {
	if m != nil {
		return m.PrivateKeyWrappingInfo
	}
	return nil
}

func init() {
	proto.RegisterType((*KeyRequest)(nil), "moc.cloudagent.security.KeyRequest")
	proto.RegisterType((*KeyResponse)(nil), "moc.cloudagent.security.KeyResponse")
	proto.RegisterType((*KeyOperationRequest)(nil), "moc.cloudagent.security.KeyOperationRequest")
	proto.RegisterType((*KeyOperationResponse)(nil), "moc.cloudagent.security.KeyOperationResponse")
	proto.RegisterType((*PrivateKeyWrappingInfo)(nil), "moc.cloudagent.security.PrivateKeyWrappingInfo")
	proto.RegisterType((*SignVerifyParams)(nil), "moc.cloudagent.security.SignVerifyParams")
	proto.RegisterType((*Key)(nil), "moc.cloudagent.security.Key")
}

func init() { proto.RegisterFile("moc_cloudagent_key.proto", fileDescriptor_d1154d4ecd5d6df6) }

var fileDescriptor_d1154d4ecd5d6df6 = []byte{
	// 864 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x55, 0x4d, 0x6f, 0xdb, 0x46,
	0x10, 0x2d, 0x2d, 0x59, 0x89, 0x46, 0x8e, 0xd3, 0x6c, 0x52, 0x67, 0x23, 0x24, 0x85, 0xaa, 0x04,
	0xa8, 0x02, 0xa4, 0x54, 0xa0, 0xb6, 0xe7, 0xc2, 0x6a, 0xdc, 0xc2, 0x65, 0x10, 0x1b, 0x2b, 0x27,
	0x01, 0x7a, 0x31, 0x28, 0x6a, 0x4c, 0x13, 0x22, 0xb9, 0xec, 0xee, 0x52, 0x01, 0x7d, 0xea, 0xb1,
	0xfd, 0x41, 0x3d, 0xf7, 0x07, 0xf4, 0xaf, 0xf4, 0xdc, 0x73, 0xc1, 0xa1, 0x68, 0xea, 0xc3, 0x12,
	0x8a, 0x22, 0x27, 0x9b, 0x33, 0xef, 0xcd, 0xbc, 0x7d, 0x33, 0xbb, 0x02, 0x1e, 0x49, 0xef, 0xdc,
	0x0b, 0x65, 0x3a, 0x71, 0x7d, 0x8c, 0xcd, 0xf9, 0x14, 0x33, 0x3b, 0x51, 0xd2, 0x48, 0xf6, 0x30,
	0x92, 0x9e, 0x5d, 0x65, 0x6c, 0x8d, 0x5e, 0xaa, 0x02, 0x93, 0xb5, 0x3f, 0xf7, 0xa5, 0xf4, 0x43,
	0xec, 0x13, 0x6c, 0x9c, 0x5e, 0xf4, 0x3f, 0x28, 0x37, 0x49, 0x50, 0xe9, 0x82, 0xd8, 0x7e, 0x48,
	0x25, 0x65, 0x14, 0xc9, 0x78, 0xfe, 0x67, 0x9e, 0x78, 0xb4, 0x90, 0x28, 0xab, 0x15, 0xa9, 0xae,
	0x01, 0x70, 0x30, 0x13, 0xf8, 0x4b, 0x8a, 0xda, 0xb0, 0x97, 0x50, 0x77, 0x30, 0xd3, 0xdc, 0xea,
	0xd4, 0x7a, 0xad, 0xc1, 0x63, 0x7b, 0x83, 0x12, 0x3b, 0xa7, 0x10, 0x92, 0x7d, 0x03, 0x77, 0x4e,
	0x12, 0x54, 0xae, 0x09, 0x64, 0x7c, 0x96, 0x25, 0xc8, 0x77, 0x3a, 0x56, 0x6f, 0x7f, 0xb0, 0x4f,
	0xd4, 0xeb, 0x8c, 0x58, 0x06, 0x75, 0x7f, 0xb7, 0xa0, 0x45, 0x6d, 0x75, 0x22, 0x63, 0x8d, 0xff,
	0xa3, 0xef, 0x00, 0x1a, 0x02, 0x75, 0x1a, 0x1a, 0x6a, 0xd8, 0x1a, 0xb4, 0xed, 0xc2, 0x1c, 0xbb,
	0x34, 0xc7, 0x1e, 0x4a, 0x19, 0xbe, 0x73, 0xc3, 0x14, 0xc5, 0x1c, 0xc9, 0x1e, 0xc0, 0xee, 0x91,
	0x52, 0x52, 0xf1, 0x5a, 0xc7, 0xea, 0x35, 0x45, 0xf1, 0xd1, 0xfd, 0x67, 0x07, 0xee, 0x3b, 0x98,
	0x55, 0x5a, 0xe7, 0x5e, 0xd8, 0x50, 0x9b, 0x62, 0xc6, 0x2d, 0x2a, 0xbf, 0x5d, 0x52, 0x0e, 0x64,
	0x1c, 0xea, 0xaf, 0x5c, 0xe3, 0x92, 0x9e, 0xe6, 0xb0, 0xfe, 0xdb, 0x1f, 0xdc, 0x12, 0x14, 0x61,
	0x2f, 0xa0, 0xe9, 0x86, 0xbe, 0x54, 0x81, 0xb9, 0x8c, 0xa8, 0x77, 0xe9, 0xcf, 0x61, 0x19, 0x15,
	0x15, 0x80, 0xbd, 0x86, 0x83, 0x93, 0xe1, 0xe8, 0xe4, 0xf5, 0xd1, 0xd9, 0xd1, 0xf9, 0xb2, 0xb5,
	0x75, 0xa2, 0xde, 0x23, 0xea, 0xa2, 0xe2, 0xe1, 0x0e, 0xb7, 0xc4, 0x67, 0x25, 0x69, 0x89, 0xc3,
	0xde, 0xc2, 0xa7, 0xa3, 0xc0, 0x8f, 0xdf, 0xa1, 0x0a, 0x2e, 0xb2, 0x53, 0x57, 0xb9, 0x91, 0xe6,
	0xbb, 0x74, 0xa4, 0xe7, 0x1b, 0x8f, 0xb4, 0x4a, 0x10, 0x6b, 0x25, 0xd8, 0x70, 0x75, 0xec, 0x0d,
	0xd2, 0x56, 0xd8, 0x74, 0xaa, 0xe4, 0x2c, 0x98, 0xa0, 0x3a, 0xf4, 0x3c, 0xd4, 0x7a, 0xe3, 0x12,
	0x5c, 0xc1, 0x83, 0x65, 0xdf, 0xe7, 0xcb, 0x50, 0x1a, 0x69, 0xad, 0x19, 0xf9, 0xf1, 0x86, 0xfe,
	0xa7, 0x05, 0x07, 0xa7, 0x2a, 0x98, 0xb9, 0x06, 0x1d, 0xcc, 0xde, 0xe7, 0xf7, 0x28, 0x88, 0xfd,
	0xe3, 0xf8, 0x42, 0xb2, 0x1e, 0xdc, 0x2d, 0xbf, 0x1d, 0xcc, 0xde, 0xb8, 0x11, 0x16, 0x4a, 0xc4,
	0x6a, 0x98, 0x0d, 0xe0, 0xde, 0x42, 0xe8, 0x34, 0x1d, 0x87, 0x81, 0x47, 0xca, 0xf6, 0xe6, 0xaa,
	0xd7, 0xd3, 0xec, 0xc7, 0x8a, 0x73, 0xb8, 0xb2, 0x13, 0x8f, 0xca, 0xc1, 0xae, 0x01, 0xc4, 0x3a,
	0xa7, 0xfb, 0x61, 0x7d, 0xb0, 0xec, 0xbb, 0xc5, 0x45, 0xb3, 0xa8, 0xe8, 0x17, 0x54, 0xf4, 0xa7,
	0xd1, 0xc9, 0x9b, 0xf7, 0x38, 0x76, 0x30, 0xcb, 0x39, 0xae, 0x49, 0x15, 0xde, 0xb8, 0x7b, 0x5d,
	0x68, 0xea, 0x12, 0xb0, 0xb4, 0xc8, 0x55, 0xb8, 0xfb, 0x77, 0x1d, 0x6a, 0x0e, 0x66, 0x8c, 0x41,
	0x3d, 0xae, 0xcc, 0xa1, 0xff, 0xd9, 0x3e, 0xec, 0x04, 0x93, 0x82, 0x28, 0x76, 0x82, 0x09, 0xeb,
	0xc2, 0x5e, 0x28, 0x3d, 0x1a, 0x2f, 0x19, 0x59, 0xcc, 0x60, 0x29, 0x96, 0xf7, 0x4c, 0xc8, 0x1b,
	0x07, 0x33, 0x5a, 0xf1, 0xd2, 0xbd, 0x2a, 0xcc, 0xbe, 0x84, 0xba, 0xc9, 0xb7, 0x6c, 0x97, 0xce,
	0x74, 0xbf, 0x38, 0x93, 0x96, 0x71, 0x71, 0xa6, 0x7c, 0x9b, 0x04, 0x01, 0xd8, 0x63, 0x68, 0xce,
	0xdc, 0x34, 0x34, 0xd4, 0xad, 0x41, 0xdd, 0xaa, 0x40, 0x9e, 0xf5, 0x95, 0x4c, 0x13, 0xca, 0xde,
	0x2a, 0xb2, 0xd7, 0x01, 0xf6, 0x14, 0x1a, 0xda, 0xb8, 0x26, 0xd5, 0xfc, 0x36, 0x6d, 0x57, 0x8b,
	0xda, 0x8c, 0x28, 0x24, 0xe6, 0x29, 0xd6, 0x81, 0xba, 0x0e, 0xae, 0x90, 0x37, 0x49, 0xc9, 0x5e,
	0x39, 0xb2, 0x51, 0x70, 0x85, 0x82, 0x32, 0xcc, 0x86, 0x5d, 0x2f, 0x55, 0x33, 0xe4, 0x40, 0x10,
	0xbe, 0x22, 0xf6, 0xfb, 0x3c, 0x97, 0xf7, 0x13, 0x05, 0x8c, 0x3d, 0x87, 0xc6, 0x34, 0xbf, 0x06,
	0x9a, 0xb7, 0x3a, 0xb5, 0x1b, 0xef, 0xb7, 0x98, 0x03, 0xd8, 0x13, 0xa8, 0x1b, 0xd7, 0xd7, 0x7c,
	0x8f, 0xf4, 0x35, 0x09, 0x78, 0xe6, 0xfa, 0x5a, 0x50, 0x98, 0xbd, 0x82, 0x27, 0x53, 0xcc, 0x84,
	0x34, 0xc4, 0xfa, 0x41, 0xe5, 0x0f, 0x59, 0xec, 0x65, 0xc7, 0xf1, 0x08, 0x3d, 0x19, 0x4f, 0x34,
	0xbf, 0xd3, 0xb1, 0x7a, 0x35, 0xb1, 0x1d, 0xc4, 0x9e, 0x01, 0x24, 0xd7, 0x37, 0x83, 0xef, 0x2f,
	0x0c, 0x64, 0x21, 0xce, 0x7c, 0x38, 0x48, 0x6e, 0xbc, 0x3f, 0xfc, 0x2e, 0x89, 0xeb, 0x6f, 0x7c,
	0x5d, 0x6e, 0xbe, 0x76, 0x62, 0x43, 0xb9, 0xc1, 0x5f, 0x16, 0xdc, 0x76, 0x30, 0x3b, 0xcc, 0x8b,
	0xb0, 0xb7, 0xd0, 0x38, 0x8e, 0x67, 0x72, 0x8a, 0xec, 0xe9, 0xd6, 0x07, 0xb9, 0x78, 0xc2, 0xdb,
	0xcf, 0xb6, 0x83, 0x8a, 0xf7, 0xa6, 0xfb, 0x09, 0xbb, 0x84, 0x5b, 0x85, 0xd9, 0xc8, 0x5e, 0x6c,
	0xa3, 0xac, 0xfe, 0x46, 0xb4, 0xbf, 0xfa, 0x8f, 0xe8, 0xb2, 0xd3, 0xf0, 0xdb, 0x9f, 0x5f, 0xfa,
	0x81, 0xb9, 0x4c, 0xc7, 0xb6, 0x27, 0xa3, 0x7e, 0x14, 0x78, 0x4a, 0x6a, 0x79, 0x61, 0xfa, 0x91,
	0xf4, 0xfa, 0x2a, 0xf1, 0xfa, 0x55, 0xa9, 0x7e, 0x59, 0xea, 0x57, 0xcb, 0x1a, 0x37, 0xe8, 0x81,
	0xfb, 0xfa, 0xdf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x89, 0x2b, 0x30, 0x07, 0x35, 0x08, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// KeyAgentClient is the client API for KeyAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type KeyAgentClient interface {
	Invoke(ctx context.Context, in *KeyRequest, opts ...grpc.CallOption) (*KeyResponse, error)
	Operate(ctx context.Context, in *KeyOperationRequest, opts ...grpc.CallOption) (*KeyOperationResponse, error)
}

type keyAgentClient struct {
	cc *grpc.ClientConn
}

func NewKeyAgentClient(cc *grpc.ClientConn) KeyAgentClient {
	return &keyAgentClient{cc}
}

func (c *keyAgentClient) Invoke(ctx context.Context, in *KeyRequest, opts ...grpc.CallOption) (*KeyResponse, error) {
	out := new(KeyResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.security.KeyAgent/Invoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAgentClient) Operate(ctx context.Context, in *KeyOperationRequest, opts ...grpc.CallOption) (*KeyOperationResponse, error) {
	out := new(KeyOperationResponse)
	err := c.cc.Invoke(ctx, "/moc.cloudagent.security.KeyAgent/Operate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyAgentServer is the server API for KeyAgent service.
type KeyAgentServer interface {
	Invoke(context.Context, *KeyRequest) (*KeyResponse, error)
	Operate(context.Context, *KeyOperationRequest) (*KeyOperationResponse, error)
}

// UnimplementedKeyAgentServer can be embedded to have forward compatible implementations.
type UnimplementedKeyAgentServer struct {
}

func (*UnimplementedKeyAgentServer) Invoke(ctx context.Context, req *KeyRequest) (*KeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invoke not implemented")
}
func (*UnimplementedKeyAgentServer) Operate(ctx context.Context, req *KeyOperationRequest) (*KeyOperationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Operate not implemented")
}

func RegisterKeyAgentServer(s *grpc.Server, srv KeyAgentServer) {
	s.RegisterService(&_KeyAgent_serviceDesc, srv)
}

func _KeyAgent_Invoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAgentServer).Invoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.security.KeyAgent/Invoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAgentServer).Invoke(ctx, req.(*KeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAgent_Operate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KeyOperationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAgentServer).Operate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/moc.cloudagent.security.KeyAgent/Operate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAgentServer).Operate(ctx, req.(*KeyOperationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _KeyAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "moc.cloudagent.security.KeyAgent",
	HandlerType: (*KeyAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Invoke",
			Handler:    _KeyAgent_Invoke_Handler,
		},
		{
			MethodName: "Operate",
			Handler:    _KeyAgent_Operate_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "moc_cloudagent_key.proto",
}
