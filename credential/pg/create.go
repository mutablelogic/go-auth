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

	// Packages
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// CreateCredential encrypts the credentials with the latest passphrase and
// stores them, replacing any credentials with the same key. It returns the
// public credential shape, excluding the passphrase version and encrypted
// payload.
func (self *Manager) CreateCredential(ctx context.Context, req schema.CredentialCreate) (_ *schema.Credential, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.pg.CreateCredential",
		attribute.String("req", req.RedactedString()),
	)
	defer func() { endSpan(err) }()

	// Check the key before encrypting the credential data
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// Encrypt the credential data
	pv, credentials, err := self.encryptCredentials(req.Credentials)
	if err != nil {
		return nil, err
	} else {
		req.Credentials = credentials
	}

	// Insert the credential record
	var result schema.Credential
	if err := self.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		return conn.With("pv", pv).Insert(ctx, &result, req)
	}); err != nil {
		return nil, dbErr(err)
	}

	// Return success
	return types.Ptr(result), nil
}
