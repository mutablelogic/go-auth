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

package manager

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
	auth "github.com/mutablelogic/go-auth"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	attribute "go.opentelemetry.io/otel/attribute"
	trace "go.opentelemetry.io/otel/trace"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// AuthConfig returns the shareable upstream provider configuration exposed by
// /auth/config. The client secret remains server-side.
func (m *Manager) AuthConfig() (_ schema.PublicClientConfigurations, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, context.Background(), "manager.AuthConfig")
	defer func() { endSpan(err) }()

	config := make(schema.PublicClientConfigurations)
	for key, provider := range m.providers {
		if provider == nil {
			continue
		}
		config[key] = provider.PublicConfig()
	}
	if len(config) == 0 {
		err = auth.ErrNotFound.With("providers are not configured")
		return nil, err
	}
	trace.SpanFromContext(ctx).SetAttributes(attribute.Int("provider_count", len(config)))
	return config, nil
}

// OIDCJWKSet returns the public JSON Web Key Set for the manager's configured
// signing keys.
func (m *Manager) OIDCJWKSet() (jwk.Set, error) {
	return oidc.PublicJWKSetForKeys(m.signer, m.keys)
}

// OIDCSign signs the supplied claims with the manager's active signing key.
// It returns an error if no signing key has been configured.
func (m *Manager) OIDCSign(claims jwt.Claims) (string, error) {
	kid, key, err := m.signingKey()
	if err != nil {
		return "", err
	}
	return oidc.SignTokenWithKeyID(kid, key, claims)
}

// OIDCVerify verifies a locally signed JWT using the configured verification
// key matching the token kid header and expected issuer.
func (m *Manager) OIDCVerify(token, issuer string) (map[string]any, error) {
	key, err := m.verificationKey(token)
	if err != nil {
		return nil, err
	}
	return oidc.VerifySignedToken(key, token, issuer)
}

// OIDCIssuer returns the canonical issuer for locally signed tokens.
func (m *Manager) Issuer() (string, error) {
	if issuer := strings.TrimSpace(m.issuer); issuer != "" {
		return issuer, nil
	} else {
		return "", auth.ErrBadParameter.With("issuer is not configured")
	}
}

// OIDCConfig returns the OIDC configuration for this server, including the issuer URL
func (m *Manager) OIDCConfig() (oidc.OIDCConfiguration, error) {
	issuer, err := m.Issuer()
	if err != nil {
		return oidc.OIDCConfiguration{}, err
	}
	return oidc.OIDCConfiguration{
		BaseConfiguration: oidc.BaseConfiguration{
			Issuer:                issuer,
			AuthorizationEndpoint: oidc.AuthorizationURL(issuer),
			TokenEndpoint:         oidc.AuthCodeURL(issuer),
			RevocationEndpoint:    oidc.AuthRevokeURL(issuer),
			ResponseTypes:         []string{oidc.ResponseTypeCode},
			GrantTypesSupported:   []string{"authorization_code", "refresh_token"},
			ScopesSupported:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
			CodeChallengeMethods:  []string{oidc.CodeChallengeMethodS256},
		},
		UserInfoEndpoint:  oidc.UserInfoURL(issuer),
		JwksURI:           oidc.JWKSURL(issuer),
		SigningAlgorithms: []string{oidc.SigningAlgorithm},
		SubjectTypes:      []string{"public"},
		ClaimsSupported:   []string{"iss", "sub", "sid", "aud", "exp", "iat", "nbf", "token_use", "refresh_counter", "email", "email_verified", "name", "groups", "scopes", "user", "session"},
	}, nil
}

// ProtectedResourceMetadata returns OAuth protected-resource metadata for this server.
func (m *Manager) ProtectedResourceMetadata(r *http.Request) (oidc.ProtectedResourceMetadata, error) {
	issuer, err := m.Issuer()
	if err != nil {
		return oidc.ProtectedResourceMetadata{}, err
	}
	return oidc.ProtectedResourceMetadata{
		Resource:               issuer,
		AuthorizationServers:   []string{issuer},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           m.Name(),
	}, nil
}

func (m *Manager) signingKey() (string, *rsa.PrivateKey, error) {
	kid := strings.TrimSpace(m.signer)
	if kid == "" {
		return "", nil, auth.ErrBadParameter.With("signing key is not configured")
	}
	key, ok := m.keys[kid]
	if !ok || key == nil {
		return "", nil, auth.ErrBadParameter.Withf("signing key %q is not configured", kid)
	}
	return kid, key, nil
}

func (m *Manager) verificationKey(token string) (*rsa.PublicKey, error) {
	kid, err := oidc.ExtractKeyID(token)
	if err != nil {
		return nil, err
	}
	key, ok := m.keys[kid]
	if !ok || key == nil {
		return nil, auth.ErrBadParameter.Withf("JWT signing key %q is not configured", kid)
	}
	return &key.PublicKey, nil
}
