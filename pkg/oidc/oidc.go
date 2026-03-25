package oidc

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/url"
	"time"

	// Packages
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	auth "github.com/djthorpe/go-auth"
	jwt "github.com/golang-jwt/jwt/v5"
	jwa "github.com/lestrrat-go/jwx/v2/jwa"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Configuration represents the OpenID Connect discovery document.
type Configuration struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string   `json:"token_endpoint,omitempty"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	JwksURI               string   `json:"jwks_uri"`
	SigningAlgorithms     []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypes          []string `json:"subject_types_supported"`
	ResponseTypes         []string `json:"response_types_supported"`
	GrantTypesSupported   []string `json:"grant_types_supported,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported,omitempty"`
	ClaimsSupported       []string `json:"claims_supported"`
}

const (
	ScopeOpenID  = "openid"
	ScopeEmail   = "email"
	ScopeProfile = "profile"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	GoogleIssuer          = "https://accounts.google.com"
	ConfigPath            = ".well-known/openid-configuration"
	ProtectedResourcePath = ".well-known/oauth-protected-resource"
	JWKSPath              = ".well-known/jwks.json"
	AuthCodePath          = "auth/code"
	UserInfoPath          = "auth/userinfo"
	SigningAlgorithm      = "RS256"
	KeyID                 = "dev-main-2026-03"
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
		return "", fmt.Errorf("claims must include a non-empty iss")
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

// JWKSURL returns the JWKS document URL for an issuer.
func JWKSURL(issuer string) string {
	uri, err := url.JoinPath(issuer, JWKSPath)
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

// UserInfoURL returns the userinfo URL for an issuer.
func UserInfoURL(issuer string) string {
	uri, err := url.JoinPath(issuer, UserInfoPath)
	if err != nil {
		return issuer
	}
	return uri
}

// SignToken serializes claims into a JWT signed with the supplied RSA private
// key. If key is nil, it returns an unsecured JWT using the "none" algorithm.
func SignToken(key *rsa.PrivateKey, claims jwt.Claims) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("claims are required")
	}
	if key == nil {
		return jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = KeyID
	return token.SignedString(key)
}

// PublicJWKSet returns a JWKS document containing the public signing key for
// the supplied RSA private key.
func PublicJWKSet(key *rsa.PrivateKey) (jwk.Set, error) {
	if key == nil {
		return nil, fmt.Errorf("private key is required")
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
	if err := publicKey.Set(jwk.KeyIDKey, KeyID); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(publicKey); err != nil {
		return nil, err
	}
	return set, nil
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
