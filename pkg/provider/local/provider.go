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

package local

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	provider "github.com/djthorpe/go-auth/pkg/provider"
	schema "github.com/djthorpe/go-auth/schema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Provider struct {
	key   string
	title string
	codec Codec
}

var _ provider.Provider = (*Provider)(nil)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	localAuthorizationCodeType = "authorization_code"
	localKey                   = "local"
	localTitle                 = "Local Issuer"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New creates the built-in local provider for a fixed issuer and signing key.
func New(issuer string, privateKey *rsa.PrivateKey) (*Provider, error) {
	codec, err := NewCodec(issuer, privateKey)
	if err != nil {
		return nil, err
	}
	return &Provider{
		key:   localKey,
		title: localTitle,
		codec: codec,
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (p *Provider) Key() string {
	return p.key
}

func (p *Provider) PublicConfig() schema.PublicClientConfiguration {
	issuer, _ := p.codec.Issuer()
	return schema.PublicClientConfiguration{
		Issuer:   strings.TrimSpace(issuer),
		ClientID: "",
	}
}

func (p *Provider) HTTPHandler() (http.HandlerFunc, *openapi.PathItem) {
	if p == nil {
		return nil, nil
	}
	return http.HandlerFunc(p.ServeHTTP), &openapi.PathItem{
		Summary:     "Local provider browser flow",
		Description: "Renders and processes the built-in local provider login form.",
	}
}

func (p *Provider) BeginAuthorization(_ context.Context, req provider.AuthorizationRequest) (*provider.AuthorizationResponse, error) {
	providerURL := strings.TrimSpace(req.ProviderURL)
	if providerURL == "" {
		return nil, fmt.Errorf("provider_url is required")
	}
	redirectURL := strings.TrimSpace(req.RedirectURL)
	if redirectURL == "" {
		return nil, fmt.Errorf("redirect_url is required")
	}
	state := strings.TrimSpace(req.State)
	if state == "" {
		return nil, fmt.Errorf("state is required")
	}
	values := url.Values{}
	values.Set("redirect_uri", redirectURL)
	values.Set("state", state)
	if nonce := strings.TrimSpace(req.Nonce); nonce != "" {
		values.Set("nonce", nonce)
	}
	if challenge := strings.TrimSpace(req.CodeChallenge); challenge != "" {
		values.Set("code_challenge", challenge)
	}
	if method := strings.TrimSpace(req.CodeChallengeMethod); method != "" {
		values.Set("code_challenge_method", method)
	}
	if loginHint := strings.TrimSpace(req.LoginHint); loginHint != "" {
		values.Set("login_hint", loginHint)
	}
	if len(req.Scopes) > 0 {
		values.Set("scope", strings.Join(req.Scopes, " "))
	}
	uri := providerURL
	if strings.Contains(uri, "?") {
		uri += "&" + values.Encode()
	} else {
		uri += "?" + values.Encode()
	}
	return &provider.AuthorizationResponse{RedirectURL: uri}, nil
}

func (p *Provider) ExchangeAuthorizationCode(_ context.Context, req provider.ExchangeRequest) (*schema.IdentityInsert, error) {
	code := strings.TrimSpace(req.Code)
	if code == "" {
		return nil, fmt.Errorf("code is required")
	}
	issuer, err := p.codec.Issuer()
	if err != nil {
		return nil, err
	}
	claims, err := p.codec.Verify(code, issuer)
	if err != nil {
		return nil, err
	}
	if err := validateAuthorizationCodeClaims(claims, req.RedirectURL, req.CodeVerifier, req.Nonce); err != nil {
		return nil, err
	}
	email, err := emailFromClaims(claims)
	if err != nil {
		return nil, err
	}
	name := nameFromEmail(email)
	return &schema.IdentityInsert{
		IdentityKey: schema.IdentityKey{
			Provider: p.key,
			Sub:      email,
		},
		IdentityMeta: schema.IdentityMeta{
			Email: email,
			Claims: map[string]any{
				"iss":   issuer,
				"sub":   email,
				"email": email,
				"name":  name,
			},
		},
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func normalizeEmail(value string) (string, error) {
	candidate := strings.TrimSpace(value)
	if candidate == "" {
		return "", fmt.Errorf("login_hint is required")
	}
	var normalized string
	if !types.IsEmail(candidate, nil, &normalized) {
		return "", fmt.Errorf("login_hint must be a valid email address")
	}
	return strings.ToLower(strings.TrimSpace(normalized)), nil
}

func emailFromClaims(claims map[string]any) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("authorization code missing email")
	}
	email, _ := claims["email"].(string)
	if strings.TrimSpace(email) == "" {
		email, _ = claims["sub"].(string)
	}
	if strings.TrimSpace(email) == "" {
		return "", fmt.Errorf("authorization code missing email")
	}
	return normalizeEmail(email)
}

func nameFromEmail(email string) string {
	if local, _, ok := strings.Cut(strings.TrimSpace(email), "@"); ok && local != "" {
		return local
	}
	return "Local User"
}

func validateAuthorizationCodeClaims(claims map[string]any, redirectURL, codeVerifier, expectedNonce string) error {
	if value, _ := claims["typ"].(string); strings.TrimSpace(value) != localAuthorizationCodeType {
		return fmt.Errorf("invalid local authorization code")
	}
	if value, _ := claims["redirect_uri"].(string); strings.TrimSpace(value) != strings.TrimSpace(redirectURL) {
		return fmt.Errorf("authorization code redirect_uri mismatch")
	}
	if expectedNonce = strings.TrimSpace(expectedNonce); expectedNonce != "" {
		actual, _ := claims["nonce"].(string)
		if strings.TrimSpace(actual) != expectedNonce {
			return fmt.Errorf("token nonce mismatch")
		}
	}
	challenge, _ := claims["code_challenge"].(string)
	challenge = strings.TrimSpace(challenge)
	if challenge == "" {
		return fmt.Errorf("code_challenge is required")
	}
	if codeVerifier == "" {
		return fmt.Errorf("code_verifier is required")
	}
	method, _ := claims["code_challenge_method"].(string)
	switch strings.TrimSpace(method) {
	case oidc.CodeChallengeMethodS256:
		sum := sha256.Sum256([]byte(codeVerifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			return fmt.Errorf("authorization code verifier mismatch")
		}
	default:
		return fmt.Errorf("unsupported code_challenge_method %q", method)
	}
	return nil
}
