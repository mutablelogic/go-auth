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

package pg

import (
	"context"
	"crypto/subtle"
	"encoding/json"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// GetCredential retrieves a credential by key, and decrypts it if the
// passphrase is the one it was encrypted with. Returns the credential as
// JSON, or ErrForbidden if the passphrase is not the credential's passphrase.
func (self *Manager) GetCredential(ctx context.Context, key schema.CredentialKey, passphrase string) (_ json.RawMessage, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.pg.GetCredential",
		attribute.String("key", key.Key),
	)
	defer func() { endSpan(err) }()

	// Fetch the credential by key, to get its passphrase version
	result, err := self.getCredential(ctx, key)
	if err != nil {
		return nil, err
	}

	// Check the passphrase is the one for the credential's passphrase
	// version, in constant time. Get resolves version zero to the latest
	// passphrase, and returns version zero when there is no passphrase for the
	// version, so the version must resolve to itself. An empty passphrase
	// never matches.
	stored, version := self.passphrases.Get(result.PV)
	if result.PV == 0 || version != result.PV || passphrase == "" || subtle.ConstantTimeCompare([]byte(stored), []byte(passphrase)) != 1 {
		return nil, auth.ErrForbidden.With("invalid passphrase")
	}

	// Decrypt the credential
	return self.decryptCredential(result)
}

// GetCredentialMeta returns the key of a credential, and the time it was
// stored, without reading or decrypting the credential, so it does not need a
// passphrase. Returns auth.ErrNotFound, which also matches pg.ErrNotFound,
// if there is no credential for the key.
func (self *Manager) GetCredentialMeta(ctx context.Context, key schema.CredentialKey) (_ *schema.Credential, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.pg.GetCredentialMeta",
		attribute.String("key", key.Key),
	)
	defer func() { endSpan(err) }()

	var result schema.Credential
	if err := self.PoolConn.With("meta", true).Get(ctx, &result, key); err != nil {
		return nil, dbErr(err)
	}

	// Return success
	return types.Ptr(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - INTERNAL USE ONLY

// GetCredentialWithoutPassphrase retrieves and decrypts a credential using the stored
// passphrase version. It is intended for internal server-side use only and must not
// be exposed via any public API or HTTP handler.
func (self *Manager) GetCredentialWithoutPassphrase(ctx context.Context, key schema.CredentialKey) (_ json.RawMessage, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.pg.GetCredentialWithoutPassphrase",
		attribute.String("key", key.Key),
	)
	defer func() { endSpan(err) }()

	// Fetch and decrypt the credential
	result, err := self.getCredential(ctx, key)
	if err != nil {
		return nil, err
	}
	return self.decryptCredential(result)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// getCredential returns the stored credential for the key, with its
// passphrase version and encrypted payload
func (self *Manager) getCredential(ctx context.Context, key schema.CredentialKey) (*schema.CredentialGet, error) {
	var result schema.CredentialGet
	if err := self.PoolConn.Get(ctx, &result, key); err != nil {
		return nil, dbErr(err)
	}
	return &result, nil
}

// decryptCredential decrypts the stored credential, and returns it as JSON
func (self *Manager) decryptCredential(result *schema.CredentialGet) (json.RawMessage, error) {
	encrypted, ok := result.Credentials.([]byte)
	if !ok {
		return nil, auth.ErrInternalServerError.With("credential payload is invalid")
	}
	var credentials json.RawMessage
	if err := self.decryptCredentials(encrypted, result.PV, &credentials); err != nil {
		return nil, err
	}
	return credentials, nil
}
