package errors

import (
	"testing"

	"go.uber.org/multierr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	moccodes "github.com/microsoft/moc/pkg/errors/codes"
	"github.com/microsoft/moc/rpc/common"
)

type NotComparableError struct {
	msg  string
	data []byte // Slices make structs not comparable
}

func (e NotComparableError) Error() string {
	return e.msg
}

func TestNewMocErrorWithError(t *testing.T) {
	tests := []struct {
		name         string
		input        *common.Error
		expectedNil  bool
		expectedCode moccodes.MocCode
		expectedErr  string
	}{
		{
			name:        "Nil error",
			input:       nil,
			expectedNil: true,
		},
		{
			name: "OK code with empty message",
			input: &common.Error{
				Code:    moccodes.OK.ToUint32(),
				Message: "",
			},
			expectedNil: true,
		},
		{
			// Tests backwards compatibility (e.g., old nodeagent communicating to new cloudagent)
			name: "OK code with message",
			input: &common.Error{
				Code:    moccodes.OK.ToUint32(),
				Message: "Some error msg with no code",
			},
			expectedNil:  false,
			expectedCode: moccodes.Unknown,
			expectedErr:  "Some error msg with no code",
		},
		{
			// Tests backwards compatibility (e.g., new nodeagent communicating to old cloudagent)
			name: "Code outside of valid range with message",
			input: &common.Error{
				Code:    2147483647,
				Message: "Some error msg with invalid code",
			},
			expectedCode: moccodes.Unknown,
			expectedErr:  "Some error msg with invalid code",
		},
		{
			name: "Non-OK code",
			input: &common.Error{
				Code:    moccodes.NotFound.ToUint32(),
				Message: legacyErrorMessages[moccodes.NotFound],
			},
			expectedNil:  false,
			expectedCode: moccodes.NotFound,
			expectedErr:  legacyErrorMessages[moccodes.NotFound],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProtoToMocError(tt.input)
			if (result == nil) != tt.expectedNil {
				t.Errorf("NewMocErrorWithError() did not return expected nil value, got: %v", result)
			} else if result != nil {
				resultCode := GetMocErrorCode(result)
				if resultCode != tt.expectedCode {
					t.Errorf("NewMocErrorWithError() code = %v, want %v", resultCode, tt.expectedCode)
				}
				if result.Error() != tt.expectedErr {
					t.Errorf("NewMocErrorWithError() error = %v, want %v", result.Error(), tt.expectedErr)
				}
			}
		})
	}
}

func TestGetMocErrorCode(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode moccodes.MocCode
	}{
		{
			name:         "Nil error",
			err:          nil,
			expectedCode: moccodes.OK,
		},
		{
			name:         "Single MocError",
			err:          NewMocError(moccodes.NotFound),
			expectedCode: moccodes.NotFound,
		},
		{
			name:         "Error with MocError cause",
			err:          Wrap(NewMocError(moccodes.InvalidInput), "wrapped error"),
			expectedCode: moccodes.InvalidInput,
		},
		{
			name:         "Error with non-MocError cause",
			err:          Wrap(New("standard error"), "wrapped error"),
			expectedCode: moccodes.Unknown,
		},
		{
			name:         "Multierr with matching MocCodes",
			err:          multierr.Combine(NotFound, NewMocError(moccodes.NotFound)),
			expectedCode: moccodes.NotFound,
		},
		{
			name:         "Multierr with different MocCodes",
			err:          multierr.Combine(NewMocError(moccodes.NotFound), NewMocError(moccodes.InvalidInput)),
			expectedCode: moccodes.Unknown,
		},
		{
			name:         "Multierr with non-MocError",
			err:          multierr.Combine(New("standard error"), NewMocError(moccodes.NotFound)),
			expectedCode: moccodes.Unknown,
		},
		{
			name:         "Multierr with nil error and matching MocCodes",
			err:          multierr.Combine(nil, NewMocError(moccodes.NotFound), NotFound),
			expectedCode: moccodes.NotFound,
		},
		{
			name: "Multierr with wrapped error and matching MocCodes",
			err: multierr.Combine(
				Wrap(NewMocError(moccodes.NotFound), "additional context"),
				Wrap(NewMocError(moccodes.NotFound), "additional context 2"),
				Wrap(NewMocError(moccodes.NotFound), "additional context 3"),
			),
			expectedCode: moccodes.NotFound,
		},
		{
			name: "Multierr with wrapped error and different MocCodes",
			err: multierr.Combine(
				Wrap(NewMocError(moccodes.NotFound), "additional context"),
				Wrap(NewMocError(moccodes.InvalidInput), "additional context 2"),
				Wrap(NewMocError(moccodes.NotFound), "additional context 3"),
			),
			expectedCode: moccodes.Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := GetMocErrorCode(tt.err)
			if code != tt.expectedCode {
				t.Errorf("GetMocErrorCode() = (%v), want (%v)", code, tt.expectedCode)
			}
		})
	}
}

func TestGetSingleMocErrorCodeAvoidsPanicOnUncomparable(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic occurred: %v", r)
		}
	}()

	// Create a NotComparableError
	detailedErr := NotComparableError{
		msg: "detailed error",
	}

	// Call getSingleMocErrorCode with the NotComparableError
	code := getSingleMocErrorCode(detailedErr)

	// Check the result
	if code != moccodes.Unknown {
		t.Errorf("expected %v, got %v", moccodes.Unknown, code)
	}
}

func TestCheckErrorAvoidsPanicOnUncomparable(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic occurred: %v", r)
		}
	}()

	// Create a NotComparableError
	detailedErr := NotComparableError{
		msg: "detailed error",
	}

	// Make sure checkError doesn't panic
	checkError(detailedErr, NotFound)
}

func TestCheckError(t *testing.T) {
	tests := []struct {
		name          string
		wrappedError  error
		err           error
		expectedEqual bool
	}{
		{
			name:          "Nil wrappedError",
			wrappedError:  nil,
			err:           NotFound,
			expectedEqual: false,
		},
		{
			name:          "Same error instance",
			wrappedError:  NotFound,
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "Different error instances with same MocCode",
			wrappedError:  NewMocError(moccodes.NotFound),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "Different MocCodes",
			wrappedError:  NewMocError(moccodes.NotFound),
			err:           NewMocError(moccodes.InvalidInput),
			expectedEqual: false,
		},
		{
			name:          "Wrapped error with Wrapf",
			wrappedError:  Wrapf(NotFound, "additional context"),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "Repeatedly wrapped error with Wrapf",
			wrappedError:  Wrapf(Wrapf(NotFound, "additional context"), "additional context 2"),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "Wrapped error with different MocCode",
			wrappedError:  Wrapf(NewMocError(moccodes.InvalidInput), "additional context"),
			err:           NotFound,
			expectedEqual: false,
		},
		{
			name:          "GRPC error with same code int doesn't match MocCode",
			wrappedError:  status.Error(codes.InvalidArgument, "invalid argument error"),
			err:           InvalidConfiguration,
			expectedEqual: false,
		},
		{
			name:          "Multierr with single matching error",
			wrappedError:  multierr.Combine(NotFound),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "Multierr with all errors having same MocCodes",
			wrappedError:  multierr.Combine(NotFound, NotFound, NewMocError(moccodes.NotFound)),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "Multierr with not all errors having same MocCodes",
			wrappedError:  multierr.Combine(NotFound, Degraded, NewMocError(moccodes.InvalidInput)),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name: "Multierr with all errors having same MocCodes using Wrapf",
			wrappedError: multierr.Combine(
				Wrapf(NotFound, "additional context"),
				Wrapf(NotFound, "additional context 2"),
				Wrapf(NewMocError(moccodes.NotFound), "additional context 3"),
			),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name: "Multierr with not all errors having same MocCodes using Wrapf",
			wrappedError: multierr.Combine(
				Wrapf(NotFound, "additional context"),
				Wrapf(InvalidInput, "additional context 2"),
				Wrapf(NewMocError(moccodes.NotFound), "additional context 3"),
			),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name: "Multierr with nested multierr all have same MocCodes",
			wrappedError: multierr.Combine(
				multierr.Combine(
					NewMocError(moccodes.NotFound),
					Wrapf(NotFound, "additional context"),
				),
				NewMocError(moccodes.NotFound),
			),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name: "Multierr with nested multierr don't all have same MocCodes",
			wrappedError: multierr.Combine(
				multierr.Combine(NotFound, NotFound),
				InvalidInput,
			),
			err:           NotFound,
			expectedEqual: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal := checkError(tt.wrappedError, tt.err)
			if equal != tt.expectedEqual {
				t.Errorf("checkError() = %v, want %v", equal, tt.expectedEqual)
			}
		})
	}
}

func TestCheckErrorBackwardsCompatible(t *testing.T) {
	tests := []struct {
		name          string
		wrappedError  error
		err           error
		expectedEqual bool
	}{
		{
			name:          "GRPC Unknown code error uses string matching",
			wrappedError:  status.Error(codes.Unknown, "this is an example description: "+NotFound.Error()),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "Error without explicit GRPC Unknown code uses string matching",
			wrappedError:  New("this is an example description: " + NotFound.Error()),
			err:           NotFound,
			expectedEqual: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal := checkError(tt.wrappedError, tt.err)
			if equal != tt.expectedEqual {
				t.Errorf("checkError() = %v, want %v", equal, tt.expectedEqual)
			}
		})
	}
}

func TestGetGRPCError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected codes.Code
	}{
		{
			name:     "NotFound error converted to grpc NotFound and has details",
			err:      NotFound,
			expected: codes.NotFound,
		},
		{
			name:     "Unknown error converted to grpc Unknown and has details",
			err:      PathNotFound,
			expected: codes.Unknown,
		},
		{
			name:     "Nil error returns nil",
			err:      nil,
			expected: codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := GetGRPCError(tt.err)
			if tt.err == nil {
				if grpcErr != nil {
					t.Errorf("expected nil, got %v", grpcErr)
				}
				return // Skip further checks
			}

			st, ok := status.FromError(grpcErr)
			if !ok {
				t.Fatalf("expected gRPC error, got %v", grpcErr)
			}
			if st.Code() != tt.expected {
				t.Errorf("expected code %v, got %v", tt.expected, st.Code())
			}
			if st.Message() != tt.err.Error() {
				t.Errorf("expected message %v, got %v", tt.err.Error(), st.Message())
			}

			var detail *common.Error
			for _, d := range st.Details() {
				if errDetail, ok := d.(*common.Error); ok {
					detail = errDetail
					break
				}
			}

			if detail == nil {
				t.Fatalf("expected a protobuf error, got nil")
			}

			if detail.Message != tt.err.Error() {
				t.Errorf("expected detail message %v, got %v", tt.err.Error(), detail.Message)
			}
		})
	}
}

func TestParseGRPCError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		expected    error
		isGRPCError bool
	}{
		{
			name:        "Parse Unknown gRPC error extracts MocCode",
			err:         GetGRPCError(PathNotFound),
			expected:    PathNotFound,
			isGRPCError: false,
		},
		{
			name:        "Parse known gRPC error retains original error",
			err:         GetGRPCError(NotFound),
			expected:    status.Error(codes.NotFound, NotFound.Error()),
			isGRPCError: true,
		},
		{
			name:        "Parse known untranslated gRPC error retains original error",
			err:         status.Error(codes.NotFound, "not found error"),
			expected:    status.Error(codes.NotFound, "not found error"),
			isGRPCError: true,
		},
		{
			name:     "Parse nil error returns nil",
			err:      nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedErr := ParseGRPCError(tt.err)
			if tt.expected == nil {
				if parsedErr != nil {
					t.Errorf("expected nil, got %v", parsedErr)
				}
				return // Skip further checks
			}

			if tt.isGRPCError {
				// Should be a known gRPC error
				st, ok := status.FromError(parsedErr)
				expStatus := status.Convert(tt.expected)

				if !ok {
					t.Errorf("expected a gRPC error, got %v", parsedErr)
				}

				if expStatus.Code() != st.Code() {
					t.Errorf("expected code '%s', got '%s'", expStatus.Code(), st.Code())
				}

				if expStatus.Message() != st.Message() {
					t.Errorf("expected code '%s', got '%s'", expStatus.Message(), st.Message())
				}
			} else {
				// Should be a MocError
				parsedErr, ok := parsedErr.(*MocError)
				if !ok {
					t.Errorf("expected MocError, got %v", parsedErr)
				}

				if GetMocErrorCode(parsedErr) != GetMocErrorCode(tt.expected) {
					t.Errorf("expected code %v, got %v", GetMocErrorCode(parsedErr), GetMocErrorCode(tt.expected))
				}
			}
		})
	}
}

func TestAreAllErrorsNotFound(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedEqual bool
	}{
		{
			name:          "NotFound error single",
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "InUse error single",
			err:           InUse,
			expectedEqual: false,
		},
		{
			name:          "nil error single",
			err:           nil,
			expectedEqual: false,
		},
		{
			name:          "Multierr with single matching error",
			err:           multierr.Combine(NotFound),
			expectedEqual: true,
		},
		{
			name:          "Multierr with all errors having same MocCodes",
			err:           multierr.Combine(NotFound, NotFound, NewMocError(moccodes.NotFound)),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name:          "Multierr with not all errors having same MocCodes",
			wrappedError:  multierr.Combine(NotFound, Degraded, NewMocError(moccodes.InvalidInput)),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name: "Multierr with all errors having same MocCodes using Wrapf",
			wrappedError: multierr.Combine(
				Wrapf(NotFound, "additional context"),
				Wrapf(NotFound, "additional context 2"),
				Wrapf(NewMocError(moccodes.NotFound), "additional context 3"),
			),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name: "Multierr with not all errors having same MocCodes using Wrapf",
			wrappedError: multierr.Combine(
				Wrapf(NotFound, "additional context"),
				Wrapf(InvalidInput, "additional context 2"),
				Wrapf(NewMocError(moccodes.NotFound), "additional context 3"),
			),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name: "Multierr with nested multierr all have same MocCodes",
			wrappedError: multierr.Combine(
				multierr.Combine(
					NewMocError(moccodes.NotFound),
					Wrapf(NotFound, "additional context"),
				),
				NewMocError(moccodes.NotFound),
			),
			err:           NotFound,
			expectedEqual: true,
		},
		{
			name: "Multierr with nested multierr don't all have same MocCodes",
			wrappedError: multierr.Combine(
				multierr.Combine(NotFound, NotFound),
				InvalidInput,
			),
			err:           NotFound,
			expectedEqual: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal := AreAllErrorsNotFound(tt.err)
			if equal != tt.expectedEqual {
				t.Errorf("AreAllErrorsNotFound() = %v, want %v", equal, tt.expectedEqual)
			}
		})
	}
}
