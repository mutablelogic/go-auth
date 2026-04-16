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
	"crypto/rsa"
	"fmt"
	"strings"

	// Packages
	oidc "github.com/mutablelogic/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// Codec signs and verifies provider-owned tokens for authorization flows.
type Codec interface {
	Issuer() (string, error)
	Sign(jwt.Claims) (string, error)
	Verify(token, issuer string) (map[string]any, error)
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type codec struct {
	issuer     string
	privateKey *rsa.PrivateKey
}

var _ Codec = codec{}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewCodec creates an RSA-backed codec for a fixed issuer.
func NewCodec(issuer string, privateKey *rsa.PrivateKey) (Codec, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	return codec{issuer: issuer, privateKey: privateKey}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c codec) Issuer() (string, error) {
	if c.issuer == "" {
		return "", fmt.Errorf("issuer is not configured")
	}
	return c.issuer, nil
}

func (c codec) Sign(claims jwt.Claims) (string, error) {
	if c.privateKey == nil {
		return "", fmt.Errorf("private key is required for signing")
	}
	return oidc.SignToken(c.privateKey, claims)
}

func (c codec) Verify(token, issuer string) (map[string]any, error) {
	if c.privateKey == nil {
		return nil, fmt.Errorf("private key is required for verification")
	}
	return oidc.VerifySignedToken(&c.privateKey.PublicKey, token, issuer)
}
