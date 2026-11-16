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
	"net/http"
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
	ErrNotModified
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
	case ErrNotModified:
		return "not modified"
	}
	return fmt.Sprintf("error code %d", int(e))
}

func (e Err) With(args ...any) error {
	return fmt.Errorf("%w: %s", e, fmt.Sprint(args...))
}

// Withf returns the error with a formatted reason. Errors in the arguments
// formatted with %w are wrapped, so errors.Is and errors.As match them as
// well as the Err.
func (e Err) Withf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{e}, args...)...)
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
	case ErrNotModified:
		return httpresponse.Err(http.StatusNotModified).With(reason)
	default:
		return httpresponse.ErrInternalError.With(reason)
	}
}

///////////////////////////////////////////////////////////////////////////////
// CLIENT ERRORS

// apiError is an error response from the API, as the auth error for its
// status, with the reason the API gave, which wraps both
type apiError struct {
	code   Err
	reason string
	err    error
}

func (e *apiError) Error() string {
	if e.reason == "" {
		return e.code.Error()
	}
	return e.code.Error() + ": " + e.reason
}

func (e *apiError) Unwrap() []error {
	return []error{e.code, e.err}
}

// ClientError converts an error response from an API to the auth error for
// its status, which wraps it, so a client's callers can check it with
// errors.Is, as they would the errors of the server's store
func ClientError(err error) error {
	if err == nil {
		return nil
	}

	// The status code, and the reason, without the status text before it
	code, reason := 0, ""
	var response httpresponse.ErrResponse
	var status httpresponse.Err
	if errors.As(err, &response) {
		code = response.Code
		reason = strings.TrimPrefix(response.Reason, http.StatusText(code)+": ")
		if reason == http.StatusText(code) {
			reason = ""
		}
	} else if errors.As(err, &status) {
		code = int(status)
	}

	// The auth error for the status
	var authErr Err
	switch code {
	case http.StatusNotModified:
		authErr = ErrNotModified
	case http.StatusBadRequest:
		authErr = ErrBadParameter
	case http.StatusUnauthorized:
		authErr = ErrInvalidProvider
	case http.StatusForbidden:
		authErr = ErrForbidden
	case http.StatusNotFound:
		authErr = ErrNotFound
	case http.StatusConflict:
		authErr = ErrConflict
	case http.StatusNotImplemented:
		authErr = ErrNotImplemented
	case http.StatusServiceUnavailable:
		authErr = ErrServiceUnavailable
	case http.StatusInternalServerError:
		authErr = ErrInternalServerError
	default:
		return err
	}
	return &apiError{code: authErr, reason: reason, err: err}
}
