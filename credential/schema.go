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

package credential

import (
	"encoding/json"
)

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// ScopeCredentialRead grants permission to list credentials, and get
	// their metadata, without their values
	ScopeCredentialRead = "credential:read"

	// ScopeCredentialWrite grants permission to set, delete and rotate
	// credentials
	ScopeCredentialWrite = "credential:write"

	// ScopeCredentialDecrypt grants permission to get a credential's value,
	// with the passphrase it was encrypted with
	ScopeCredentialDecrypt = "credential:decrypt"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// CredentialSet is a request to store a credential, replacing any credential
// with the key, and its description, when it's set
type CredentialSet struct {
	Key         string          `json:"key" help:"Credential key, an identifier"`
	Credentials json.RawMessage `json:"credentials" help:"Credential value, which can be any JSON value"`
	Description *string         `json:"description,omitempty" help:"Credential description, such as what it's for, which is kept when it isn't set, and removed when it's empty"`
}

// CredentialDescription is a request to change a credential's description,
// without its value
type CredentialDescription struct {
	Description string `json:"description" help:"Credential description, such as what it's for, which is removed when it's empty"`
}

// CredentialList is the stored credentials, without their values
type CredentialList struct {
	Count uint64       `json:"count"`
	Body  []Credential `json:"body,omitempty"`
}

// CredentialCode is the code of a sign-in, which a client authorized, at a
// loopback address, with PKCE, which the server exchanges, with the
// client's secret, and stores the grant of, as the credential
type CredentialCode struct {
	Code         string `json:"code" help:"Code of the sign-in, which the authorization server redirected with"`
	CodeVerifier string `json:"code_verifier" help:"PKCE verifier of the code's challenge"`
	RedirectURI  string `json:"redirect_uri" help:"Loopback address the code was redirected to"`
}

// CredentialAuthorize asks for the URL a person signs in at, in a browser,
// with a server's web client, which redirects to the server's callback,
// rather than a loopback address, with the scopes which are asked for
type CredentialAuthorize struct {
	RedirectURI string   `json:"redirect_uri" help:"URL of the server's callback, credential/callback, as the browser reaches it, which is registered with the web client"`
	Scopes      []string `json:"scopes,omitempty" help:"Scopes to ask for, such as those a sign-in error says"`
}

// CredentialAuthorization is the URL a person signs in at, in a browser,
// which redirects to the server's callback, which stores the sign-in
type CredentialAuthorization struct {
	URL string `json:"url" help:"URL to sign in at, which expires after a while"`
}

// CredentialSignIn is a sign-in which is stored, as the credential, without
// its tokens
type CredentialSignIn struct {
	Key    string   `json:"key" help:"Credential key, of the sign-in"`
	Issuer string   `json:"issuer" help:"Authorization server which was signed in with"`
	Scopes []string `json:"scopes,omitempty" help:"Scopes the server granted, when it says"`
}
