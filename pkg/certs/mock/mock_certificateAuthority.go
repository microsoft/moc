// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/microsoft/moc/pkg/certs (interfaces: Revocation)

// Package mock_certs is a generated GoMock package.
package mock_certs

import (
	x509 "crypto/x509"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockRevocation is a mock of Revocation interface.
type MockRevocation struct {
	ctrl     *gomock.Controller
	recorder *MockRevocationMockRecorder
}

// MockRevocationMockRecorder is the mock recorder for MockRevocation.
type MockRevocationMockRecorder struct {
	mock *MockRevocation
}

// NewMockRevocation creates a new mock instance.
func NewMockRevocation(ctrl *gomock.Controller) *MockRevocation {
	mock := &MockRevocation{ctrl: ctrl}
	mock.recorder = &MockRevocationMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRevocation) EXPECT() *MockRevocationMockRecorder {
	return m.recorder
}

// IsRevoked mocks base method.
func (m *MockRevocation) IsRevoked(arg0 *x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRevoked", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// IsRevoked indicates an expected call of IsRevoked.
func (mr *MockRevocationMockRecorder) IsRevoked(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRevoked", reflect.TypeOf((*MockRevocation)(nil).IsRevoked), arg0)
}
