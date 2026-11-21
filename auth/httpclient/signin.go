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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	oauth2 "golang.org/x/oauth2"
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

// SignInCode is the code of a sign-in, which a client authorized, such as at
// a loopback address, with PKCE, which it sends to the server, which
// exchanges it, as it has the client's secret, and stores the grant, as the
// credential
type SignInCode struct {
	Credential   string `json:"credential"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
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

// AuthCodeURL returns the URL a person signs in at, with the client, and
// the scopes, which redirects to the URI, with the state, and the challenge
// of the PKCE verifier, with the options, such as for a refresh token, when
// the server needs one to issue it, as Google does with
// access_type=offline
func (s SignIn) AuthCodeURL(redirectURI, state, verifier string, opts ...oauth2.AuthCodeOption) string {
	config := oauth2.Config{
		ClientID:    s.ClientID,
		Endpoint:    oauth2.Endpoint{AuthURL: s.Server.AuthorizationEndpoint},
		RedirectURL: redirectURI,
		Scopes:      s.Scopes,
	}
	return config.AuthCodeURL(state, append([]oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}, opts...)...)
}

// ParseRegistration returns the client of the JSON, which has its
// client_id, and client_secret, or has them in "installed" or "web", as the
// file Google's console downloads for a client does, or is a string of that
// JSON, as a credential from a file, or the environment, can be. Returns
// ErrBadParameter when it isn't one, or has no client_id.
func ParseRegistration(data []byte) (*Registration, error) {
	var value string
	if json.Unmarshal(data, &value) == nil {
		data = []byte(value)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, goauth.ErrBadParameter.With("not a JSON object, of the client_id and client_secret of an OAuth client")
	}
	for _, kind := range []string{"installed", "web"} {
		if nested, exists := object[kind]; exists {
			data = nested
			break
		}
	}
	var client Registration
	if err := json.Unmarshal(data, &client); err != nil {
		return nil, goauth.ErrBadParameter.Withf("not an OAuth client: %v", err)
	} else if strings.TrimSpace(client.ClientID) == "" {
		return nil, goauth.ErrBadParameter.With("an OAuth client with no client_id")
	}
	return &Registration{ClientID: client.ClientID, ClientSecret: client.ClientSecret}, nil
}

// authStyle returns how a client authenticates at the server's token
// endpoint, of the methods its metadata says it supports: its secret in
// the request's body, of client_secret_post, or in its header, of
// client_secret_basic, or else whichever the server accepts
func authStyle(server ServerMetadata) oauth2.AuthStyle {
	methods := server.TokenEndpointAuthMethodsSupported
	switch {
	case slices.Contains(methods, "client_secret_post"):
		return oauth2.AuthStyleInParams
	case slices.Contains(methods, "client_secret_basic"):
		return oauth2.AuthStyleInHeader
	default:
		return oauth2.AuthStyleAutoDetect
	}
}

// ClientKind returns what an OAuth client is, of the file Google's console
// downloads: ClientDesktop, of "installed", which redirects to any loopback
// port, ClientWeb, of "web", which redirects to the URLs it registers, or
// "", when it doesn't say, such as of its client_id and client_secret alone
func ClientKind(data []byte) string {
	var value string
	if json.Unmarshal(data, &value) == nil {
		data = []byte(value)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return ""
	}
	switch {
	case object["installed"] != nil:
		return ClientDesktop
	case object["web"] != nil:
		return ClientWeb
	default:
		return ""
	}
}

// The kinds of an OAuth client, of ClientKind
const (
	ClientDesktop = "installed"
	ClientWeb     = "web"
)

// ExchangeCode exchanges the code of a sign-in, with its PKCE verifier, at
// the server's token endpoint, with the client, whose secret, when it has
// one, is sent in the form, and returns the grant, with its tokens, and the
// scopes the server granted, when it says, without the client's secret, to
// be stored. Returns ErrBadParameter when there's no code, or verifier, or
// the server refuses it, and ErrServiceUnavailable when it fails.
func ExchangeCode(ctx context.Context, server ServerMetadata, client Registration, code SignInCode) (*Grant, error) {
	switch {
	case code.Code == "" || code.CodeVerifier == "":
		return nil, goauth.ErrBadParameter.With("a sign-in needs its code, and verifier")
	case server.TokenEndpoint == "":
		return nil, goauth.ErrBadParameter.Withf("server %q has no token endpoint", server.Issuer)
	case client.ClientID == "":
		return nil, goauth.ErrBadParameter.With("no client")
	}
	config := oauth2.Config{
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: server.AuthorizationEndpoint, TokenURL: server.TokenEndpoint, AuthStyle: authStyle(server)},
		RedirectURL:  code.RedirectURI,
	}
	token, err := config.Exchange(ctx, code.Code, oauth2.VerifierOption(code.CodeVerifier))
	// A refusal is a bad parameter, but a failure, such as a 5xx, or 429,
	// which oauth2 says the same way, is unavailable, so it can be tried
	// again
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) && !retryable(retrieve) {
		return nil, goauth.ErrBadParameter.Withf("signing in with %s: %w", server.Issuer, err)
	} else if err != nil {
		return nil, goauth.ErrServiceUnavailable.Withf("signing in with %s: %w", server.Issuer, err)
	}

	// The scopes are those the server granted, when it says
	var scopes []string
	if scope, ok := token.Extra("scope").(string); ok {
		scopes = strings.Fields(scope)
	}
	return &Grant{
		Server:      server,
		Client:      Registration{ClientID: client.ClientID},
		RedirectURI: code.RedirectURI,
		Scopes:      scopes,
		Token:       &oauth2.Token{AccessToken: token.AccessToken, TokenType: token.TokenType, RefreshToken: token.RefreshToken, Expiry: token.Expiry},
	}, nil
}

// retryable returns true when a token endpoint's error is a failure, such
// as a 5xx, or 429, rather than a refusal
func retryable(err *oauth2.RetrieveError) bool {
	return err.Response != nil && (err.Response.StatusCode >= 500 || err.Response.StatusCode == 429)
}
