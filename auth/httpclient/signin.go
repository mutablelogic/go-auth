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
	"fmt"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// SignIn is what's needed for a person to sign in, so a resource can be
// used: the authorization server, the client which is signed in to, the
// scopes which are asked for, and the key of the credential which is stored
// once they've signed in. It has no secrets, so a server returns it to its
// client, which authorizes, such as with Authorize, at a loopback address,
// and the server, which has the client's secret, exchanges the code.
type SignIn struct {
	Server     ServerMetadata `json:"server"`
	ClientID   string         `json:"client_id"`
	Scopes     []string       `json:"scopes,omitempty"`
	Credential string         `json:"credential,omitempty"`
}

// SignInError is the error of a resource whose user needs to sign in, such
// as when they haven't, or their grant is for another client, or doesn't
// have the scopes the resource needs, or is revoked, with how they sign in
type SignInError struct {
	SignIn
	Err error
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewSignInError returns the error, with how to sign in
func NewSignInError(signIn SignIn, err error) *SignInError {
	return &SignInError{SignIn: signIn, Err: err}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (e *SignInError) Error() string {
	if e.Server.Issuer == "" {
		return fmt.Sprint(e.Err)
	}
	return fmt.Sprintf("%v: sign in with %s", e.Err, e.Server.Issuer)
}

// Unwrap returns the error, so it's matched with errors.Is
func (e *SignInError) Unwrap() error {
	return e.Err
}

// SignInOf returns what's needed to sign in, of an error which is a
// SignInError, or nil
func SignInOf(err error) *SignIn {
	var e *SignInError
	if errors.As(err, &e) {
		return &e.SignIn
	}
	return nil
}
