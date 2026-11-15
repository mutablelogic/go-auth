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
// with the key
type CredentialSet struct {
	Key         string          `json:"key" help:"Credential key, an identifier"`
	Credentials json.RawMessage `json:"credentials" help:"Credential value, which can be any JSON value"`
}

// CredentialList is the stored credentials, without their values
type CredentialList struct {
	Count uint64       `json:"count"`
	Body  []Credential `json:"body,omitempty"`
}
