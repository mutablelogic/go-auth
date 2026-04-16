// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"errors"
	"fmt"
	"strings"

	// Packages
	"github.com/mutablelogic/go-server/pkg/httpresponse"
)

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	ErrSuccess Err = iota
	ErrNotFound
	ErrBadParameter
	ErrNotImplemented
	ErrConflict
	ErrServiceUnavailable
	ErrInternalServerError
	ErrInvalidProvider
	ErrForbidden
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Err represents a typed application error.
type Err int

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (e Err) Error() string {
	switch e {
	case ErrSuccess:
		return "success"
	case ErrNotFound:
		return "not found"
	case ErrBadParameter:
		return "bad parameter"
	case ErrNotImplemented:
		return "not implemented"
	case ErrConflict:
		return "conflict"
	case ErrServiceUnavailable:
		return "service unavailable"
	case ErrInternalServerError:
		return "internal server error"
	case ErrInvalidProvider:
		return "invalid auth provider"
	case ErrForbidden:
		return "forbidden"
	}
	return fmt.Sprintf("error code %d", int(e))
}

func (e Err) With(args ...any) error {
	return fmt.Errorf("%w: %s", e, fmt.Sprint(args...))
}

func (e Err) Withf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", e, fmt.Sprintf(format, args...))
}

// HTTPError converts an auth.Err to an appropriate httpresponse error, preserving the
// reason message.
func HTTPError(err error) error {
	var authErr Err
	if !errors.As(err, &authErr) {
		return err
	}
	reason := strings.TrimPrefix(err.Error(), authErr.Error()+": ")
	switch authErr {
	case ErrSuccess:
		return nil
	case ErrNotFound:
		return httpresponse.ErrNotFound.With(reason)
	case ErrBadParameter:
		return httpresponse.ErrBadRequest.With(reason)
	case ErrConflict:
		return httpresponse.ErrConflict.With(reason)
	case ErrNotImplemented:
		return httpresponse.ErrNotImplemented.With(reason)
	case ErrServiceUnavailable:
		return httpresponse.ErrServiceUnavailable.With(reason)
	case ErrInternalServerError:
		return httpresponse.ErrInternalError.With(reason)
	case ErrInvalidProvider:
		return httpresponse.ErrNotAuthorized.With(reason)
	case ErrForbidden:
		return httpresponse.ErrForbidden.With(reason)
	default:
		return httpresponse.ErrInternalError.With(reason)
	}
}
