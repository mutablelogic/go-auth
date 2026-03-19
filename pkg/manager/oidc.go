package manager

import (
	"crypto/rsa"
	"encoding/json"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	OIDCSigningAlgorithm = "RS256"
	OIDCKeyID            = "dev-main-2026-03"
)

func (m *Manager) OIDCJWKSet() (map[string]any, error) {
	return OIDCJWKSetPEM(m.privateKey)
}

func (m *Manager) OIDCSign(claims jwt.Claims) (string, error) {
	return OIDCSignPEM(m.privateKey, claims)
}

func OIDCSignPEM(value string, claims jwt.Claims) (string, error) {
	key, err := parseOIDCPrivateKeyPEM(value)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = OIDCKeyID
	return token.SignedString(key)
}

func OIDCJWKSetPEM(value string) (map[string]any, error) {
	key, err := parseOIDCJWKPEM(value)
	if err != nil {
		return nil, err
	}
	publicKey, err := jwk.PublicKeyOf(key)
	if err != nil {
		return nil, err
	}
	if err := publicKey.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, err
	}
	if err := publicKey.Set(jwk.AlgorithmKey, jwa.SignatureAlgorithm(OIDCSigningAlgorithm)); err != nil {
		return nil, err
	}
	if err := publicKey.Set(jwk.KeyIDKey, OIDCKeyID); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(publicKey); err != nil {
		return nil, err
	}
	data, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}
	var jwks map[string]any
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, err
	}
	return jwks, nil
}

func parseOIDCJWKPEM(value string) (jwk.Key, error) {
	key, err := jwk.ParseKey([]byte(value), jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func parseOIDCPrivateKeyPEM(value string) (*rsa.PrivateKey, error) {
	key, err := parseOIDCJWKPEM(value)
	if err != nil {
		return nil, err
	}
	var raw rsa.PrivateKey
	if err := key.Raw(&raw); err != nil {
		return nil, err
	}
	return &raw, nil
}
