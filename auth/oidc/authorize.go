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

package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// AuthorizationCodeFlow contains the generated state required to start an
// interactive OAuth2/OIDC authorization code flow with optional PKCE.
type AuthorizationCodeFlow struct {
	Provider                 string   `json:"provider,omitempty"`
	Issuer                   string   `json:"issuer,omitempty"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	AuthorizationURL         string   `json:"authorization_url"`
	TokenEndpoint            string   `json:"token_endpoint,omitempty"`
	TokenEndpointAuthMethods []string `json:"-"`
	ClientID                 string   `json:"client_id"`
	RedirectURL              string   `json:"redirect_url"`
	ResponseType             string   `json:"response_type"`
	Scopes                   []string `json:"scopes,omitempty"`
	State                    string   `json:"state"`
	Nonce                    string   `json:"nonce,omitempty"`
	CodeChallenge            string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod      string   `json:"code_challenge_method,omitempty"`
	CodeVerifier             string   `json:"code_verifier,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	ResponseTypeCode         = "code"
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
	randomTokenBytes         = 32
)

var DefaultOIDCAuthorizationScopes = []string{ScopeOpenID, ScopeEmail, ScopeProfile}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewAuthorizationCodeFlow generates state and PKCE data needed to begin an
// interactive OAuth2/OIDC authorization code flow using the supplied discovery
// document. A nonce is added only for OIDC-capable configurations. clientID may
// be empty for provider-routed server-side exchanges where the server holds the
// upstream client credentials.
func NewAuthorizationCodeFlow(config BaseConfiguration, clientID, redirectURL string, scopes ...string) (*AuthorizationCodeFlow, error) {
	clientID = strings.TrimSpace(clientID)
	redirectURL = strings.TrimSpace(redirectURL)
	if strings.TrimSpace(config.AuthorizationEndpoint) == "" {
		return nil, fmt.Errorf("authorization endpoint is required")
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("redirect URL is required")
	}
	state, err := randomToken(randomTokenBytes)
	if err != nil {
		return nil, err
	}
	flow := &AuthorizationCodeFlow{
		Issuer:                   strings.TrimSpace(config.Issuer),
		AuthorizationEndpoint:    strings.TrimSpace(config.AuthorizationEndpoint),
		TokenEndpoint:            strings.TrimSpace(config.TokenEndpoint),
		TokenEndpointAuthMethods: compactValues(config.TokenEndpointAuthMethods),
		ClientID:                 clientID,
		RedirectURL:              redirectURL,
		ResponseType:             ResponseTypeCode,
		Scopes:                   scopes,
		State:                    state,
	}
	if config.NonceSupported {
		nonce, err := randomToken(randomTokenBytes)
		if err != nil {
			return nil, err
		}
		flow.Nonce = nonce
	}
	if method := PreferredCodeChallengeMethod(config.CodeChallengeMethods); method != "" {
		verifier, challenge, err := NewCodeChallenge(method)
		if err != nil {
			return nil, err
		}
		flow.CodeChallengeMethod = method
		flow.CodeVerifier = verifier
		flow.CodeChallenge = challenge
	}
	uri, err := flow.URL()
	if err != nil {
		return nil, err
	}
	flow.AuthorizationURL = uri
	return flow, nil
}

// ValidateCallback validates the authorization callback code and state
// against the flow state and returns the authorization code.
func (flow *AuthorizationCodeFlow) ValidateCallback(code, state string) (string, error) {
	if flow == nil {
		return "", fmt.Errorf("authorization flow is required")
	}
	code = strings.TrimSpace(code)
	state = strings.TrimSpace(state)
	if expected := strings.TrimSpace(flow.State); expected != "" && state != expected {
		if state == "" {
			return "", fmt.Errorf("authorization callback missing state")
		}
		return "", fmt.Errorf("authorization callback state mismatch")
	}
	if code == "" {
		return "", fmt.Errorf("authorization callback missing code")
	}
	return code, nil
}

// AuthorizationScopes returns caller-supplied scopes, or preferred default
// OIDC scopes filtered to those advertised by discovery when present.
func AuthorizationScopes(config OIDCConfiguration, scopes ...string) []string {
	if len(scopes) > 0 {
		return append([]string(nil), scopes...)
	}
	if len(config.ScopesSupported) == 0 {
		return append([]string(nil), DefaultOIDCAuthorizationScopes...)
	}
	supported := make(map[string]struct{}, len(config.ScopesSupported))
	for _, scope := range config.ScopesSupported {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			supported[scope] = struct{}{}
		}
	}
	selected := make([]string, 0, len(DefaultOIDCAuthorizationScopes))
	for _, scope := range DefaultOIDCAuthorizationScopes {
		if _, ok := supported[scope]; ok {
			selected = append(selected, scope)
		}
	}
	if len(selected) > 0 {
		return selected
	}
	return append([]string(nil), DefaultOIDCAuthorizationScopes...)
}

// OAuthAuthorizationScopes returns caller-supplied scopes, or advertised
// OAuth scopes when present. OAuth metadata has no implicit openid/profile default.
func OAuthAuthorizationScopes(config OAuthConfiguration, scopes ...string) []string {
	if len(scopes) > 0 {
		return append([]string(nil), scopes...)
	}
	selected := compactValues(config.ScopesSupported)
	if len(selected) == 0 {
		return nil
	}
	return selected
}

// URL returns the authorization URL for the flow.
func (flow AuthorizationCodeFlow) URL() (string, error) {
	values := url.Values{}
	if clientID := strings.TrimSpace(flow.ClientID); clientID != "" {
		values.Set("client_id", clientID)
	}
	values.Set("redirect_uri", flow.RedirectURL)
	values.Set("response_type", flow.ResponseType)
	values.Set("state", flow.State)
	if len(flow.Scopes) > 0 {
		values.Set("scope", strings.Join(flow.Scopes, " "))
	}
	if nonce := strings.TrimSpace(flow.Nonce); nonce != "" {
		values.Set("nonce", nonce)
	}
	if challenge := strings.TrimSpace(flow.CodeChallenge); challenge != "" {
		values.Set("code_challenge", challenge)
	}
	if method := strings.TrimSpace(flow.CodeChallengeMethod); method != "" {
		values.Set("code_challenge_method", method)
	}
	uri, err := url.Parse(flow.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	uri.RawQuery = values.Encode()
	return uri.String(), nil
}

// PreferredCodeChallengeMethod chooses the strongest supported PKCE method.
func PreferredCodeChallengeMethod(methods []string) string {
	var plain bool
	for _, method := range methods {
		switch strings.TrimSpace(method) {
		case CodeChallengeMethodS256:
			return CodeChallengeMethodS256
		case CodeChallengeMethodPlain:
			plain = true
		}
	}
	if plain {
		return CodeChallengeMethodPlain
	}
	return ""
}

// NewCodeChallenge generates a code verifier and derived code challenge using
// the requested PKCE method.
func NewCodeChallenge(method string) (string, string, error) {
	method = strings.TrimSpace(method)
	if method == "" {
		method = CodeChallengeMethodS256
	}
	verifier, err := randomToken(48)
	if err != nil {
		return "", "", err
	}
	switch method {
	case CodeChallengeMethodPlain:
		return verifier, verifier, nil
	case CodeChallengeMethodS256:
		sum := sha256.Sum256([]byte(verifier))
		return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", "", fmt.Errorf("unsupported code challenge method %q", method)
	}
}

func randomToken(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("token size must be greater than zero")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func compactValues(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}
