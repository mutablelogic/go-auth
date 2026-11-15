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

package httpclient

import (
	"errors"
	"net/http"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	client "github.com/mutablelogic/go-client"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Client calls the credential API, which credential/httphandler serves
type Client struct {
	*client.Client
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a client of the credential API at the URL, such as
// "http://localhost:8080/api"
func New(url string, opts ...client.ClientOpt) (*Client, error) {
	c, err := client.New(append(opts, client.OptEndpoint(url))...)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// apiError is an error response from the API, as the auth error for its
// status, with the reason the API gave, which wraps both
type apiError struct {
	code   auth.Err
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

// clientErr converts an error response from the API to the auth error for
// its status, which wraps it, so callers can check it with errors.Is, as
// they would the errors of a credential store
func clientErr(err error) error {
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
	var authErr auth.Err
	switch code {
	case http.StatusNotModified:
		authErr = auth.ErrNotModified
	case http.StatusBadRequest:
		authErr = auth.ErrBadParameter
	case http.StatusForbidden:
		authErr = auth.ErrForbidden
	case http.StatusNotFound:
		authErr = auth.ErrNotFound
	case http.StatusConflict:
		authErr = auth.ErrConflict
	case http.StatusNotImplemented:
		authErr = auth.ErrNotImplemented
	case http.StatusServiceUnavailable:
		authErr = auth.ErrServiceUnavailable
	case http.StatusInternalServerError:
		authErr = auth.ErrInternalServerError
	default:
		return err
	}
	return &apiError{code: authErr, reason: reason, err: err}
}
