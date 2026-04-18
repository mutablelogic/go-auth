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
	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ProtectedResourceMetadata describes this server as an OAuth protected
// resource.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource" jsonschema:"Canonical resource identifier for this protected resource server." format:"uri" example:"http://127.0.0.1:8084"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty" jsonschema:"Authorization servers that issue bearer tokens accepted by this resource."`
	ScopesSupported        []string `json:"scopes_supported,omitempty" jsonschema:"Scopes that may be used when requesting access to this resource."`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty" jsonschema:"Bearer token transport methods accepted by this resource."`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty" jsonschema:"Human-readable documentation URL for this protected resource." format:"uri"`
	ResourceName           string   `json:"resource_name,omitempty" jsonschema:"Display name for this protected resource." example:"go-auth"`
}

// JSONWebKey represents a public RSA signing key published in the JWKS
// document for locally issued tokens.
type JSONWebKey struct {
	Algorithm string `json:"alg" jsonschema:"Signing algorithm associated with this key." example:"RS256"`
	Exponent  string `json:"e" jsonschema:"Base64url-encoded RSA public exponent." example:"AQAB"`
	KeyID     string `json:"kid,omitempty" jsonschema:"Key identifier used in JWT headers to select this key." example:"main"`
	KeyType   string `json:"kty" jsonschema:"Cryptographic key type." example:"RSA"`
	Modulus   string `json:"n" jsonschema:"Base64url-encoded RSA public modulus." example:"xP1HjDfXoKFxANOMQ_iq8PeNp2C9dKvXQFTIeIGOtB9c4OnPmGPUytnJ-I3x45gtsWsyeq1lJqcDaA8LiqVE-IkPdG-ahyX510NKdh-D3hKTRvwpInCtjeVQ4LZ2tW2Md7kT6dBhb-fc6QnWTkwhwl5do3OWNtXg8nxypS6jcN84fY1xPo99HRDLnoXbFfcFXUt2XbNKMh5SfHr2yh3Sbk_s3Mo4v1DmpIILS22EIAoQKk15pazsF24RhKXI719BDh7NwIiOW8dwJ2e9B16ZFZksV4wYF65lW_EPzOAiVincX9ZlXY4wIUQP2Pe-DarMI7pD96nOql9rXA5KbyukSQ"`
	Use       string `json:"use,omitempty" jsonschema:"Intended use of the key." example:"sig"`
}

// JSONWebKeySet is the public JWKS document returned for locally issued
// tokens.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys" jsonschema:"Public signing keys published by this issuer for JWT verification."`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (c ProtectedResourceMetadata) String() string {
	return types.Stringify(c)
}
