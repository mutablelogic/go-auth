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
	"context"
	"encoding/json"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Credential is a stored credential's key, its description, when it was
// last changed, and whether it needs rotating, as it's encrypted with an
// older passphrase than the latest, which only managers which encrypt with
// their own passphrases say, without its value
type Credential struct {
	Key         string    `json:"key"`
	Description string    `json:"description,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
	Rotate      bool      `json:"rotate,omitempty"`
}

type CredentialProvider interface {
	// Expand expands the given value using the credential provider, substituting any
	// credentials $PLACEHOLDER or ${PLACEHOLDER} as needed.
	Expand(ctx context.Context, value string) (string, error)

	// Get returns the credential for the key, as JSON
	Get(ctx context.Context, key string) (json.RawMessage, error)

	// Set stores the credential for the key, which is JSON, replacing any
	// credential with the key
	Set(ctx context.Context, key string, value json.RawMessage) error

	// Delete removes the stored credential for the key, and returns
	// ErrNotFound when there isn't one, or ErrNotImplemented when the
	// provider can't store credentials, such as the environment. A
	// credential from the environment can't be deleted.
	Delete(ctx context.Context, key string) error
}

// CredentialManager is a provider which manages its stored credentials,
// and can list and describe them
type CredentialManager interface {
	CredentialProvider

	// List returns the stored credentials, in key order, without their
	// values. Credentials from the environment aren't listed.
	List(ctx context.Context) ([]Credential, error)

	// Describe sets the description of the stored credential for the key,
	// such as what it's for, or removes it, when it's empty, and returns
	// ErrNotFound when there isn't one. Descriptions aren't secret, and
	// List returns them.
	Describe(ctx context.Context, key, description string) error
}

// CredentialRotator is a provider which encrypts credentials with its own
// passphrases, and can re-encrypt them with the latest one
type CredentialRotator interface {
	// Rotate re-encrypts the credential for the key with the latest
	// passphrase, and returns ErrNotModified when it already uses it, or
	// ErrNotFound when there isn't one
	Rotate(ctx context.Context, key string) error
}

// CredentialDecrypter is a provider which encrypts credentials with its own
// passphrases, and returns a credential only to a caller who knows the
// passphrase it was encrypted with
type CredentialDecrypter interface {
	// Decrypt returns the credential for the key, as JSON, when the
	// passphrase is the one it was encrypted with. Returns ErrForbidden when
	// it isn't, or ErrNotFound when there's no credential for the key.
	Decrypt(ctx context.Context, key, passphrase string) (json.RawMessage, error)
}
