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
	"context"
	"crypto/rsa"
	"net/url"
	"sort"
	"time"

	// Packages
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	jwa "github.com/lestrrat-go/jwx/v2/jwa"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
	auth "github.com/mutablelogic/go-auth"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// BaseConfiguration contains the fields shared by OIDC and
// OAuth authorization server metadata documents.
type BaseConfiguration struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint            string   `json:"token_endpoint,omitempty"`
	RegistrationEndpoint     string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint       string   `json:"revocation_endpoint,omitempty"`
	ResponseTypes            []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported      []string `json:"grant_types_supported,omitempty"`
	ScopesSupported          []string `json:"scopes_supported,omitempty"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethods []string `json:"-"`
	NonceSupported           bool     `json:"-"`
}

// OIDCConfiguration represents the OpenID Connect discovery document.
type OIDCConfiguration struct {
	BaseConfiguration
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri"`
	SigningAlgorithms                 []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypes                      []string `json:"subject_types_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// OAuthConfiguration represents OAuth 2.0 Authorization Server Metadata.
type OAuthConfiguration struct {
	BaseConfiguration
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	GoogleIssuer          = "https://accounts.google.com"
	ConfigPath            = ".well-known/openid-configuration"
	OAuthConfigPath       = ".well-known/oauth-authorization-server"
	ProtectedResourcePath = ".well-known/oauth-protected-resource"
	JWKSPath              = ".well-known/jwks.json"
	AuthorizationPath     = "auth/authorize"
	AuthCodePath          = "auth/code"
	AuthRevokePath        = "auth/revoke"
	UserInfoPath          = "auth/userinfo"
	SigningAlgorithm      = "RS256"
)

const (
	ScopeOpenID  = "openid"
	ScopeEmail   = "email"
	ScopeProfile = "profile"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// IssueToken applies standard OIDC claim defaults and serializes the claims
// into a JWT.
func IssueToken(key *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	if claims == nil {
		claims = jwt.MapClaims{}
	}

	if issuer, ok := claims["iss"].(string); !ok || issuer == "" {
		return "", auth.ErrConflict.With("claims must include a non-empty iss")
	}

	// Set iat, nbf, and exp if not already set.
	now := time.Now().UTC()
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["nbf"]; !ok {
		claims["nbf"] = now.Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(time.Hour).Unix()
	}

	return SignToken(key, claims)
}

// ConfigURL returns the discovery document URL for an issuer.
func ConfigURL(issuer string) string {
	uri, err := url.JoinPath(issuer, ConfigPath)
	if err != nil {
		return issuer
	}
	return uri
}

// OAuthConfigURL returns the OAuth authorization server metadata URL for an issuer.
func OAuthConfigURL(issuer string) string {
	uri, err := url.JoinPath(issuer, OAuthConfigPath)
	if err != nil {
		return issuer
	}
	return uri
}

// JWKSURL returns the JWKS document URL for an issuer.
func JWKSURL(issuer string) string {
	uri, err := url.JoinPath(issuer, JWKSPath)
	if err != nil {
		return issuer
	}
	return uri
}

// AuthorizationURL returns the authorization endpoint URL for an issuer.
func AuthorizationURL(issuer string) string {
	uri, err := url.JoinPath(issuer, AuthorizationPath)
	if err != nil {
		return issuer
	}
	return uri
}

// AuthCodeURL returns the local authorization-code exchange URL for an issuer.
func AuthCodeURL(issuer string) string {
	uri, err := url.JoinPath(issuer, AuthCodePath)
	if err != nil {
		return issuer
	}
	return uri
}

// AuthRevokeURL returns the local token revocation URL for an issuer.
func AuthRevokeURL(issuer string) string {
	uri, err := url.JoinPath(issuer, AuthRevokePath)
	if err != nil {
		return issuer
	}
	return uri
}

// UserInfoURL returns the userinfo URL for an issuer.
func UserInfoURL(issuer string) string {
	uri, err := url.JoinPath(issuer, UserInfoPath)
	if err != nil {
		return issuer
	}
	return uri
}

// SignToken serializes claims into a JWT signed with the supplied RSA private
// key without setting a kid header. If key is nil, it returns an unsecured JWT
// using the "none" algorithm.
func SignToken(key *rsa.PrivateKey, claims jwt.Claims) (string, error) {
	return SignTokenWithKeyID("", key, claims)
}

// SignTokenWithKeyID serializes claims into a JWT signed with the supplied RSA
// private key and uses kid for the JWT kid header.
func SignTokenWithKeyID(kid string, key *rsa.PrivateKey, claims jwt.Claims) (string, error) {
	if claims == nil {
		return "", auth.ErrConflict.With("claims are required")
	}
	if key == nil {
		return jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	return token.SignedString(key)
}

// PublicJWKSet returns a JWKS document containing the public signing key for
// the supplied RSA private key without assigning a kid.
func PublicJWKSet(key *rsa.PrivateKey) (jwk.Set, error) {
	publicKey, err := publicJWK("", key)
	if err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(publicKey); err != nil {
		return nil, err
	}
	return set, nil
}

// PublicJWKSetForKeys returns a JWKS document containing the supplied public
// signing keys. When activeKeyID is present, it is added first.
func PublicJWKSetForKeys(activeKeyID string, keys map[string]*rsa.PrivateKey) (jwk.Set, error) {
	if len(keys) == 0 {
		return nil, auth.ErrConflict.With("private key is required")
	}

	set := jwk.NewSet()
	seen := make(map[string]struct{}, len(keys))
	appendKey := func(kid string, key *rsa.PrivateKey) error {
		publicKey, err := publicJWK(kid, key)
		if err != nil {
			return err
		}
		if err := set.AddKey(publicKey); err != nil {
			return err
		}
		seen[kid] = struct{}{}
		return nil
	}

	if activeKeyID != "" {
		key, ok := keys[activeKeyID]
		if !ok {
			return nil, auth.ErrBadParameter.Withf("signing key %q is not configured", activeKeyID)
		}
		if err := appendKey(activeKeyID, key); err != nil {
			return nil, err
		}
	}

	keyIDs := make([]string, 0, len(keys))
	for kid := range keys {
		if _, ok := seen[kid]; ok {
			continue
		}
		keyIDs = append(keyIDs, kid)
	}
	sort.Strings(keyIDs)
	for _, kid := range keyIDs {
		if err := appendKey(kid, keys[kid]); err != nil {
			return nil, err
		}
	}

	return set, nil
}

func publicJWK(kid string, key *rsa.PrivateKey) (jwk.Key, error) {
	if key == nil {
		return nil, auth.ErrConflict.With("private key is required")
	}
	parsed, err := jwk.FromRaw(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	publicKey, err := jwk.PublicKeyOf(parsed)
	if err != nil {
		return nil, err
	}
	if err := publicKey.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, err
	}
	if err := publicKey.Set(jwk.AlgorithmKey, jwa.SignatureAlgorithm(SigningAlgorithm)); err != nil {
		return nil, err
	}
	if kid != "" {
		if err := publicKey.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, err
		}
	}
	return publicKey, nil
}

// ExtractIssuer returns the iss claim from a JWT payload without verifying the
// signature.
func ExtractIssuer(token string) (string, error) {
	claims := new(jwt.RegisteredClaims)
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return "", auth.ErrBadParameter.Withf("parse JWT: %v", err)
	}
	if claims.Issuer == "" {
		return "", auth.ErrBadParameter.With("JWT missing iss claim")
	}
	return claims.Issuer, nil
}

// ExtractKeyID returns the kid header from a JWT payload without verifying the
// signature.
func ExtractKeyID(token string) (string, error) {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return "", auth.ErrBadParameter.Withf("parse JWT: %v", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	if kid == "" {
		return "", auth.ErrBadParameter.With("JWT missing kid header")
	}
	return kid, nil
}

// VerifyToken verifies a JWT using OIDC discovery based on its issuer and
// returns the decoded claims.
func VerifyToken(ctx context.Context, token string) (map[string]any, error) {
	issuer, err := ExtractIssuer(token)
	if err != nil {
		return nil, err
	}
	provider, err := coreoidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&coreoidc.Config{
		SkipClientIDCheck: true,
	})
	verified, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := verified.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// VerifySignedToken verifies a locally signed JWT with the supplied RSA public
// key and optionally checks the expected issuer.
func VerifySignedToken(key *rsa.PublicKey, token, issuer string) (map[string]any, error) {
	if key == nil {
		return nil, auth.ErrBadParameter.With("public key is required")
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != SigningAlgorithm {
			return nil, auth.ErrBadParameter.Withf("unexpected signing algorithm %q", token.Method.Alg())
		}
		return key, nil
	})
	if err != nil {
		return nil, auth.ErrBadParameter.Withf("verify JWT: %v", err)
	}
	if !parsed.Valid {
		return nil, auth.ErrBadParameter.With("invalid JWT")
	}
	if issuer != "" {
		if value, ok := claims["iss"].(string); !ok || value != issuer {
			return nil, auth.ErrBadParameter.With("JWT issuer does not match this server")
		}
	}
	return claims, nil
}
