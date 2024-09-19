package errors

import (
	"testing"

	"go.uber.org/multierr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	moccodes "github.com/microsoft/moc/pkg/errors/codes"
)

func TestGetMocErrorCode(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedCode  moccodes.MocCode
		expectedValid bool
	}{
		{
			name:          "Nil error",
			err:           nil,
			expectedCode:  moccodes.OK,
			expectedValid: true,
		},
		{
			name:          "Single MocError",
			err:           NewMocError(moccodes.NotFound),
			expectedCode:  moccodes.NotFound,
			expectedValid: true,
		},
		{
			name:          "Error with MocError cause",
			err:           Wrap(NewMocError(moccodes.InvalidInput), "wrapped error"),
			expectedCode:  moccodes.InvalidInput,
			expectedValid: true,
		},
		{
			name:          "Error with non-MocError cause",
			err:           Wrap(New("standard error"), "wrapped error"),
			expectedCode:  moccodes.Unknown,
			expectedValid: false,
		},
		{
			name:          "Multierr with matching MocCodes",
			err:           multierr.Combine(NotFound, NewMocError(moccodes.NotFound)),
			expectedCode:  moccodes.NotFound,
			expectedValid: true,
		},
		{
			name:          "Multierr with different MocCodes",
			err:           multierr.Combine(NewMocError(moccodes.NotFound), NewMocError(moccodes.InvalidInput)),
			expectedCode:  moccodes.MultipleErrors,
			expectedValid: false,
		},
		{
			name:          "Multierr with non-MocError",
			err:           multierr.Combine(New("standard error"), NewMocError(moccodes.NotFound)),
			expectedCode:  moccodes.MultipleErrors,
			expectedValid: false,
		},
		{
			name:          "Multierr with nil error and matching MocCodes",
			err:           multierr.Combine(nil, NewMocError(moccodes.NotFound), NotFound),
			expectedCode:  moccodes.NotFound,
			expectedValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, valid := GetMocErrorCode(tt.err)
			if code != tt.expectedCode || valid != tt.expectedValid {
				t.Errorf("GetMocErrorCode() = (%v, %v), want (%v, %v)", code, valid, tt.expectedCode, tt.expectedValid)
			}
		})
	}
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
			name:          "GRPC Unknown error doesn't match MocCode",
			wrappedError:  status.Error(codes.Unknown, "unknown error"),
			err:           Unknown,
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
			expectedEqual: false,
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
			expectedEqual: false,
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
			expectedEqual: false,
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
