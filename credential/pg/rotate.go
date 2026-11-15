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
	"errors"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RotateCredential re-encrypts a credential with the latest passphrase
// version, without changing its value. Returns ErrNotModified if the
// credential already uses the latest version, or ErrConflict if the
// credential was changed or deleted while it was being rotated.
func (self *Manager) RotateCredential(ctx context.Context, key schema.CredentialKey) (_ *schema.Credential, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.pg.RotateCredential",
		attribute.String("key", key.Key),
	)
	defer func() { endSpan(err) }()

	// Fetch the credential, to get its passphrase version and encrypted data
	current, err := self.getCredential(ctx, key)
	if err != nil {
		return nil, err
	}
	encrypted, ok := current.Credentials.([]byte)
	if !ok {
		return nil, auth.ErrInternalServerError.With("credential payload is invalid")
	}

	// Determine the latest passphrase version
	_, latestPV := self.passphrases.Get(0)
	if latestPV == 0 {
		return nil, auth.ErrServiceUnavailable.With("no encryption passphrase configured for credentials")
	}

	// Nothing to do if the credential already uses the latest version
	if current.PV == latestPV {
		return nil, auth.ErrNotModified.Withf("credential %q already uses the latest passphrase version", key.Key)
	}

	// Decrypt with the credential's passphrase version, and encrypt with the
	// latest. The decrypted data is re-encrypted as-is, so the value is
	// unchanged.
	plaintext, err := self.passphrases.Decrypt(current.PV, string(encrypted))
	if err != nil {
		return nil, auth.ErrBadParameter.Withf("%w", err)
	}
	pv, ciphertext, err := self.passphrases.Encrypt(latestPV, plaintext)
	if err != nil {
		return nil, auth.ErrBadParameter.Withf("%w", err)
	}

	// Replace the encrypted data, only if it hasn't changed since it was read
	var result schema.Credential
	if err := self.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		return conn.Insert(ctx, &result, schema.CredentialRotate{
			CredentialKey:  key,
			PV:             pv,
			Credentials:    []byte(ciphertext),
			OldPV:          current.PV,
			OldCredentials: encrypted,
		})
	}); errors.Is(pg.NormalizeError(err), pg.ErrNotFound) {
		return nil, auth.ErrConflict.Withf("credential %q was changed while it was being rotated", key.Key)
	} else if err != nil {
		return nil, dbErr(err)
	}

	// Return success
	return types.Ptr(result), nil
}
