// Code generated by protoc-gen-go. DO NOT EDIT.
// source: moc_common_security.proto

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

type Algorithm int32

const (
	Algorithm_A_UNKNOWN  Algorithm = 0
	Algorithm_RSA15      Algorithm = 1
	Algorithm_RSAOAEP    Algorithm = 2
	Algorithm_RSAOAEP256 Algorithm = 3
	Algorithm_A256KW     Algorithm = 4
	Algorithm_A256CBC    Algorithm = 5
)

var Algorithm_name = map[int32]string{
	0: "A_UNKNOWN",
	1: "RSA15",
	2: "RSAOAEP",
	3: "RSAOAEP256",
	4: "A256KW",
	5: "A256CBC",
}

var Algorithm_value = map[string]int32{
	"A_UNKNOWN":  0,
	"RSA15":      1,
	"RSAOAEP":    2,
	"RSAOAEP256": 3,
	"A256KW":     4,
	"A256CBC":    5,
}

func (x Algorithm) String() string {
	return proto.EnumName(Algorithm_name, int32(x))
}

func (Algorithm) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{0}
}

type JSONWebKeySignatureAlgorithm int32

const (
	JSONWebKeySignatureAlgorithm_RSNULL JSONWebKeySignatureAlgorithm = 0
	JSONWebKeySignatureAlgorithm_ES256  JSONWebKeySignatureAlgorithm = 1
	JSONWebKeySignatureAlgorithm_ES256K JSONWebKeySignatureAlgorithm = 2
	JSONWebKeySignatureAlgorithm_ES384  JSONWebKeySignatureAlgorithm = 3
	JSONWebKeySignatureAlgorithm_ES512  JSONWebKeySignatureAlgorithm = 4
	JSONWebKeySignatureAlgorithm_PS256  JSONWebKeySignatureAlgorithm = 5
	JSONWebKeySignatureAlgorithm_PS384  JSONWebKeySignatureAlgorithm = 6
	JSONWebKeySignatureAlgorithm_PS512  JSONWebKeySignatureAlgorithm = 7
	JSONWebKeySignatureAlgorithm_RS256  JSONWebKeySignatureAlgorithm = 8
	JSONWebKeySignatureAlgorithm_RS384  JSONWebKeySignatureAlgorithm = 9
	JSONWebKeySignatureAlgorithm_RS512  JSONWebKeySignatureAlgorithm = 10
)

var JSONWebKeySignatureAlgorithm_name = map[int32]string{
	0:  "RSNULL",
	1:  "ES256",
	2:  "ES256K",
	3:  "ES384",
	4:  "ES512",
	5:  "PS256",
	6:  "PS384",
	7:  "PS512",
	8:  "RS256",
	9:  "RS384",
	10: "RS512",
}

var JSONWebKeySignatureAlgorithm_value = map[string]int32{
	"RSNULL": 0,
	"ES256":  1,
	"ES256K": 2,
	"ES384":  3,
	"ES512":  4,
	"PS256":  5,
	"PS384":  6,
	"PS512":  7,
	"RS256":  8,
	"RS384":  9,
	"RS512":  10,
}

func (x JSONWebKeySignatureAlgorithm) String() string {
	return proto.EnumName(JSONWebKeySignatureAlgorithm_name, int32(x))
}

func (JSONWebKeySignatureAlgorithm) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{1}
}

type KeyOperation int32

const (
	KeyOperation_ENCRYPT   KeyOperation = 0 // Deprecated: Do not use.
	KeyOperation_DECRYPT   KeyOperation = 1 // Deprecated: Do not use.
	KeyOperation_WRAPKEY   KeyOperation = 2 // Deprecated: Do not use.
	KeyOperation_UNWRAPKEY KeyOperation = 3 // Deprecated: Do not use.
	KeyOperation_SIGN      KeyOperation = 4 // Deprecated: Do not use.
	KeyOperation_VERIFY    KeyOperation = 5 // Deprecated: Do not use.
)

var KeyOperation_name = map[int32]string{
	0: "ENCRYPT",
	1: "DECRYPT",
	2: "WRAPKEY",
	3: "UNWRAPKEY",
	4: "SIGN",
	5: "VERIFY",
}

var KeyOperation_value = map[string]int32{
	"ENCRYPT":   0,
	"DECRYPT":   1,
	"WRAPKEY":   2,
	"UNWRAPKEY": 3,
	"SIGN":      4,
	"VERIFY":    5,
}

func (x KeyOperation) String() string {
	return proto.EnumName(KeyOperation_name, int32(x))
}

func (KeyOperation) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{2}
}

// https://docs.microsoft.com/en-us/rest/api/keyvault/createkey/createkey#jsonwebkeytype
type JsonWebKeyType int32

const (
	JsonWebKeyType_EC      JsonWebKeyType = 0
	JsonWebKeyType_EC_HSM  JsonWebKeyType = 1
	JsonWebKeyType_RSA     JsonWebKeyType = 2
	JsonWebKeyType_RSA_HSM JsonWebKeyType = 3
	JsonWebKeyType_OCT     JsonWebKeyType = 4
	JsonWebKeyType_AES     JsonWebKeyType = 5
)

var JsonWebKeyType_name = map[int32]string{
	0: "EC",
	1: "EC_HSM",
	2: "RSA",
	3: "RSA_HSM",
	4: "OCT",
	5: "AES",
}

var JsonWebKeyType_value = map[string]int32{
	"EC":      0,
	"EC_HSM":  1,
	"RSA":     2,
	"RSA_HSM": 3,
	"OCT":     4,
	"AES":     5,
}

func (x JsonWebKeyType) String() string {
	return proto.EnumName(JsonWebKeyType_name, int32(x))
}

func (JsonWebKeyType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{3}
}

type JsonWebKeyCurveName int32

const (
	JsonWebKeyCurveName_P_256  JsonWebKeyCurveName = 0
	JsonWebKeyCurveName_P_256K JsonWebKeyCurveName = 1
	JsonWebKeyCurveName_P_384  JsonWebKeyCurveName = 2
	JsonWebKeyCurveName_P_521  JsonWebKeyCurveName = 3
)

var JsonWebKeyCurveName_name = map[int32]string{
	0: "P_256",
	1: "P_256K",
	2: "P_384",
	3: "P_521",
}

var JsonWebKeyCurveName_value = map[string]int32{
	"P_256":  0,
	"P_256K": 1,
	"P_384":  2,
	"P_521":  3,
}

func (x JsonWebKeyCurveName) String() string {
	return proto.EnumName(JsonWebKeyCurveName_name, int32(x))
}

func (JsonWebKeyCurveName) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{4}
}

type KeySize int32

const (
	KeySize_K_UNKNOWN KeySize = 0
	KeySize__256      KeySize = 1
	KeySize__2048     KeySize = 2
	KeySize__3072     KeySize = 3
	KeySize__4096     KeySize = 4
)

var KeySize_name = map[int32]string{
	0: "K_UNKNOWN",
	1: "_256",
	2: "_2048",
	3: "_3072",
	4: "_4096",
}

var KeySize_value = map[string]int32{
	"K_UNKNOWN": 0,
	"_256":      1,
	"_2048":     2,
	"_3072":     3,
	"_4096":     4,
}

func (x KeySize) String() string {
	return proto.EnumName(KeySize_name, int32(x))
}

func (KeySize) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{5}
}

type IdentityOperation int32

const (
	IdentityOperation_REVOKE IdentityOperation = 0 // Deprecated: Do not use.
	IdentityOperation_ROTATE IdentityOperation = 1 // Deprecated: Do not use.
)

var IdentityOperation_name = map[int32]string{
	0: "REVOKE",
	1: "ROTATE",
}

var IdentityOperation_value = map[string]int32{
	"REVOKE": 0,
	"ROTATE": 1,
}

func (x IdentityOperation) String() string {
	return proto.EnumName(IdentityOperation_name, int32(x))
}

func (IdentityOperation) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{6}
}

type IdentityCertificateOperation int32

const (
	IdentityCertificateOperation_CREATE_CERTIFICATE IdentityCertificateOperation = 0 // Deprecated: Do not use.
	IdentityCertificateOperation_RENEW_CERTIFICATE  IdentityCertificateOperation = 1 // Deprecated: Do not use.
)

var IdentityCertificateOperation_name = map[int32]string{
	0: "CREATE_CERTIFICATE",
	1: "RENEW_CERTIFICATE",
}

var IdentityCertificateOperation_value = map[string]int32{
	"CREATE_CERTIFICATE": 0,
	"RENEW_CERTIFICATE":  1,
}

func (x IdentityCertificateOperation) String() string {
	return proto.EnumName(IdentityCertificateOperation_name, int32(x))
}

func (IdentityCertificateOperation) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{7}
}

type KeyWrappingAlgorithm int32

const (
	KeyWrappingAlgorithm_CKM_RSA_AES_KEY_WRAP KeyWrappingAlgorithm = 0
	KeyWrappingAlgorithm_RSA_AES_KEY_WRAP_256 KeyWrappingAlgorithm = 1
	KeyWrappingAlgorithm_RSA_AES_KEY_WRAP_384 KeyWrappingAlgorithm = 2
)

var KeyWrappingAlgorithm_name = map[int32]string{
	0: "CKM_RSA_AES_KEY_WRAP",
	1: "RSA_AES_KEY_WRAP_256",
	2: "RSA_AES_KEY_WRAP_384",
}

var KeyWrappingAlgorithm_value = map[string]int32{
	"CKM_RSA_AES_KEY_WRAP": 0,
	"RSA_AES_KEY_WRAP_256": 1,
	"RSA_AES_KEY_WRAP_384": 2,
}

func (x KeyWrappingAlgorithm) String() string {
	return proto.EnumName(KeyWrappingAlgorithm_name, int32(x))
}

func (KeyWrappingAlgorithm) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{8}
}

type Scope struct {
	Location             string       `protobuf:"bytes,1,opt,name=location,proto3" json:"location,omitempty"`
	ResourceGroup        string       `protobuf:"bytes,2,opt,name=resourceGroup,proto3" json:"resourceGroup,omitempty"`
	ProviderType         ProviderType `protobuf:"varint,3,opt,name=providerType,proto3,enum=moc.ProviderType" json:"providerType,omitempty"`
	Resource             string       `protobuf:"bytes,4,opt,name=resource,proto3" json:"resource,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *Scope) Reset()         { *m = Scope{} }
func (m *Scope) String() string { return proto.CompactTextString(m) }
func (*Scope) ProtoMessage()    {}
func (*Scope) Descriptor() ([]byte, []int) {
	return fileDescriptor_0d3874efde778ac1, []int{0}
}

func (m *Scope) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Scope.Unmarshal(m, b)
}
func (m *Scope) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Scope.Marshal(b, m, deterministic)
}
func (m *Scope) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Scope.Merge(m, src)
}
func (m *Scope) XXX_Size() int {
	return xxx_messageInfo_Scope.Size(m)
}
func (m *Scope) XXX_DiscardUnknown() {
	xxx_messageInfo_Scope.DiscardUnknown(m)
}

var xxx_messageInfo_Scope proto.InternalMessageInfo

func (m *Scope) GetLocation() string {
	if m != nil {
		return m.Location
	}
	return ""
}

func (m *Scope) GetResourceGroup() string {
	if m != nil {
		return m.ResourceGroup
	}
	return ""
}

func (m *Scope) GetProviderType() ProviderType {
	if m != nil {
		return m.ProviderType
	}
	return ProviderType_AnyProvider
}

func (m *Scope) GetResource() string {
	if m != nil {
		return m.Resource
	}
	return ""
}

func init() {
	proto.RegisterEnum("moc.Algorithm", Algorithm_name, Algorithm_value)
	proto.RegisterEnum("moc.JSONWebKeySignatureAlgorithm", JSONWebKeySignatureAlgorithm_name, JSONWebKeySignatureAlgorithm_value)
	proto.RegisterEnum("moc.KeyOperation", KeyOperation_name, KeyOperation_value)
	proto.RegisterEnum("moc.JsonWebKeyType", JsonWebKeyType_name, JsonWebKeyType_value)
	proto.RegisterEnum("moc.JsonWebKeyCurveName", JsonWebKeyCurveName_name, JsonWebKeyCurveName_value)
	proto.RegisterEnum("moc.KeySize", KeySize_name, KeySize_value)
	proto.RegisterEnum("moc.IdentityOperation", IdentityOperation_name, IdentityOperation_value)
	proto.RegisterEnum("moc.IdentityCertificateOperation", IdentityCertificateOperation_name, IdentityCertificateOperation_value)
	proto.RegisterEnum("moc.KeyWrappingAlgorithm", KeyWrappingAlgorithm_name, KeyWrappingAlgorithm_value)
	proto.RegisterType((*Scope)(nil), "moc.Scope")
}

func init() { proto.RegisterFile("moc_common_security.proto", fileDescriptor_0d3874efde778ac1) }

var fileDescriptor_0d3874efde778ac1 = []byte{
	// 660 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x54, 0x4b, 0x6f, 0xda, 0x4c,
	0x14, 0xc5, 0x0f, 0x5e, 0xf7, 0x4b, 0xf8, 0x06, 0x37, 0x52, 0x09, 0xca, 0x22, 0xea, 0x43, 0x8a,
	0xbc, 0x80, 0x04, 0x42, 0x9a, 0x2e, 0x1d, 0x77, 0x92, 0x12, 0x27, 0x36, 0xb2, 0x4d, 0x10, 0xed,
	0xc2, 0x22, 0xce, 0x84, 0x58, 0x8a, 0x19, 0x6b, 0x30, 0x91, 0xe8, 0x3f, 0xa9, 0xd4, 0x1f, 0x5b,
	0xcd, 0x0c, 0x14, 0x52, 0x75, 0xc5, 0xb9, 0xe7, 0x9e, 0xb9, 0x97, 0x39, 0xc7, 0x1a, 0xd8, 0x4f,
	0x69, 0x1c, 0xc5, 0x34, 0x4d, 0xe9, 0x2c, 0x9a, 0x93, 0x78, 0xc1, 0x92, 0x7c, 0xd9, 0xca, 0x18,
	0xcd, 0xa9, 0xa1, 0xa5, 0x34, 0x6e, 0xbe, 0xdd, 0xea, 0xcb, 0x1f, 0xd9, 0x7d, 0xf7, 0x4b, 0x81,
	0x62, 0x10, 0xd3, 0x8c, 0x18, 0x4d, 0xa8, 0x3c, 0xd3, 0x78, 0x92, 0x27, 0x74, 0xd6, 0x50, 0x0e,
	0x95, 0xa3, 0xaa, 0xff, 0xa7, 0x36, 0x3e, 0xc0, 0x2e, 0x23, 0x73, 0xba, 0x60, 0x31, 0xb9, 0x62,
	0x74, 0x91, 0x35, 0x54, 0x21, 0x78, 0x4d, 0x1a, 0x3d, 0xd8, 0xc9, 0x18, 0x7d, 0x49, 0x1e, 0x08,
	0x0b, 0x97, 0x19, 0x69, 0x68, 0x87, 0xca, 0x51, 0xad, 0x53, 0x6f, 0xa5, 0x34, 0x6e, 0x0d, 0xb6,
	0x1a, 0xfe, 0x2b, 0x19, 0x5f, 0xbc, 0x9e, 0xd3, 0xd0, 0xe5, 0xe2, 0x75, 0x6d, 0x7e, 0x87, 0xaa,
	0xf5, 0x3c, 0xa5, 0x2c, 0xc9, 0x9f, 0x52, 0x63, 0x17, 0xaa, 0x56, 0x34, 0x74, 0x1d, 0xd7, 0x1b,
	0xb9, 0xa8, 0x60, 0x54, 0xa1, 0xe8, 0x07, 0xd6, 0x49, 0x0f, 0x29, 0xc6, 0x7f, 0x50, 0xf6, 0x03,
	0xcb, 0xb3, 0xf0, 0x00, 0xa9, 0x46, 0x0d, 0x60, 0x55, 0x74, 0x7a, 0x67, 0x48, 0x33, 0x00, 0x4a,
	0x56, 0xa7, 0x77, 0xe6, 0x8c, 0x90, 0xce, 0x85, 0x1c, 0xdb, 0x17, 0x36, 0x2a, 0x9a, 0x3f, 0x15,
	0x38, 0xb8, 0x0e, 0x3c, 0x77, 0x44, 0xee, 0x1d, 0xb2, 0x0c, 0x92, 0xe9, 0x6c, 0x92, 0x2f, 0x18,
	0xd9, 0x2c, 0x04, 0x28, 0xf9, 0x81, 0x3b, 0xbc, 0xb9, 0x91, 0xdb, 0x70, 0xc0, 0x07, 0x2a, 0x9c,
	0x16, 0xd0, 0x41, 0xaa, 0xa4, 0xbb, 0xe7, 0xa7, 0x48, 0x93, 0xb0, 0x77, 0xd2, 0x41, 0x3a, 0x87,
	0x03, 0x21, 0x2e, 0x4a, 0xc8, 0x05, 0x25, 0x09, 0xb9, 0xa0, 0x2c, 0xff, 0x3b, 0x17, 0x54, 0x24,
	0xe4, 0x82, 0xaa, 0x84, 0x5c, 0x00, 0x26, 0x83, 0x1d, 0x87, 0x2c, 0xbd, 0x8c, 0x30, 0x99, 0xc0,
	0xff, 0x50, 0xc6, 0xae, 0xed, 0x8f, 0x07, 0x21, 0x2a, 0x34, 0xd5, 0x8a, 0xc2, 0x89, 0x2f, 0x58,
	0x12, 0xca, 0x9a, 0x18, 0xf9, 0xd6, 0xc0, 0xc1, 0x63, 0xa4, 0x0a, 0xa2, 0x0e, 0xd5, 0xa1, 0xbb,
	0xa6, 0x34, 0x41, 0xed, 0x80, 0x1e, 0xf4, 0xaf, 0x5c, 0xa4, 0x8b, 0xaa, 0x06, 0xa5, 0x3b, 0xec,
	0xf7, 0x2f, 0xc7, 0xa8, 0xc8, 0x6b, 0xf3, 0x06, 0x6a, 0xd7, 0x73, 0x3a, 0x93, 0x76, 0x88, 0x68,
	0x4a, 0xa0, 0x62, 0x1b, 0x15, 0xc4, 0x8d, 0xed, 0xe8, 0x6b, 0x70, 0x8b, 0x14, 0xa3, 0x0c, 0x9a,
	0x1f, 0x58, 0x48, 0x5d, 0x99, 0x2e, 0x58, 0x8d, 0xb3, 0x9e, 0x1d, 0x22, 0x9d, 0x03, 0x0b, 0x07,
	0xa8, 0x68, 0x5e, 0xc0, 0x9b, 0xcd, 0x34, 0x7b, 0xc1, 0x5e, 0x88, 0x3b, 0x49, 0x89, 0x30, 0x21,
	0xe2, 0x37, 0x17, 0x53, 0x05, 0x74, 0x90, 0x22, 0x69, 0xee, 0x82, 0x2a, 0x61, 0xaf, 0x73, 0x82,
	0x34, 0xd3, 0x86, 0xb2, 0x48, 0xe6, 0x07, 0xe1, 0xe1, 0x3b, 0x5b, 0xe1, 0x57, 0x40, 0x8f, 0x64,
	0x1a, 0x55, 0x28, 0x46, 0x9d, 0xe3, 0xd3, 0x73, 0x79, 0x32, 0xea, 0x1e, 0x7f, 0xea, 0xc8, 0x30,
	0xa2, 0xd3, 0xe3, 0xcf, 0x67, 0x48, 0x37, 0xbb, 0x50, 0xef, 0x3f, 0x90, 0x59, 0x9e, 0xe4, 0x5b,
	0x7e, 0xd6, 0xa0, 0xe4, 0xe3, 0x3b, 0xcf, 0xc1, 0x2b, 0x3b, 0x79, 0xed, 0x85, 0x56, 0x88, 0xa5,
	0x9b, 0xe6, 0x10, 0x0e, 0xd6, 0x87, 0x6c, 0xc2, 0xf2, 0xe4, 0x31, 0x89, 0x27, 0x39, 0xd9, 0x9c,
	0x6f, 0x82, 0x61, 0xfb, 0xd8, 0x0a, 0x71, 0x64, 0x63, 0x3f, 0xec, 0x5f, 0xf6, 0x6d, 0x7e, 0x56,
	0xce, 0xda, 0x87, 0xba, 0x8f, 0x5d, 0x3c, 0x7a, 0xd5, 0x92, 0x63, 0x1f, 0x60, 0xcf, 0x21, 0xcb,
	0x11, 0x9b, 0x64, 0x59, 0x32, 0x9b, 0x6e, 0xbe, 0xb4, 0x06, 0xec, 0xd9, 0xce, 0x6d, 0xc4, 0xfd,
	0xb4, 0x70, 0x10, 0x39, 0x78, 0x1c, 0xf1, 0xe4, 0x50, 0x81, 0x77, 0xfe, 0x66, 0x57, 0x17, 0xff,
	0x57, 0x47, 0x38, 0x78, 0xf1, 0xf1, 0xdb, 0xfb, 0x69, 0x92, 0x3f, 0x2d, 0xee, 0x5b, 0x31, 0x4d,
	0xdb, 0x69, 0x12, 0x33, 0x3a, 0xa7, 0x8f, 0x79, 0x3b, 0xa5, 0x71, 0x9b, 0x65, 0x71, 0x5b, 0xbe,
	0x00, 0xf7, 0x25, 0xf1, 0x04, 0x74, 0x7f, 0x07, 0x00, 0x00, 0xff, 0xff, 0x90, 0xcf, 0x45, 0xcc,
	0x3d, 0x04, 0x00, 0x00,
}
