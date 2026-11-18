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
	"errors"
	"fmt"
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
		Endpoint:     oauth2.Endpoint{AuthURL: server.AuthorizationEndpoint, TokenURL: server.TokenEndpoint, AuthStyle: oauth2.AuthStyleInParams},
		RedirectURL:  code.RedirectURI,
	}
	token, err := config.Exchange(ctx, code.Code, oauth2.VerifierOption(code.CodeVerifier))
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) {
		return nil, goauth.ErrBadParameter.Withf("signing in with %s: %w", server.Issuer, err)
	} else if err != nil {
		return nil, goauth.ErrServiceUnavailable.Withf("signing in with %s: %v", server.Issuer, err)
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
