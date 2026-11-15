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

// DescribeCredential sets the description of a credential, or removes it,
// when it's empty, without changing when it was updated, and returns the
// credential. Returns pg.ErrNotFound, as auth.ErrNotFound, when there's no
// credential for the key.
func (self *Manager) DescribeCredential(ctx context.Context, key schema.CredentialKey, description string) (_ *schema.Credential, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.pg.DescribeCredential",
		attribute.String("key", key.Key),
	)
	defer func() { endSpan(err) }()

	var result schema.Credential
	if err := self.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		return conn.Update(ctx, &result, key, schema.CredentialDescribe{Description: description})
	}); err != nil {
		return nil, dbErr(err)
	}

	// Return success
	return types.Ptr(result), nil
}
