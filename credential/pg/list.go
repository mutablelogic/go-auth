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
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ListCredentials returns a page of credentials in key order, without their
// encrypted payloads. When Rotate is set, only the credentials which need
// rotating to the latest passphrase version are returned, or when it is
// false, only those which don't.
func (self *Manager) ListCredentials(ctx context.Context, req schema.CredentialListRequest) (_ *schema.CredentialList, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.pg.ListCredentials",
		attribute.String("req", req.String()),
	)
	defer func() { endSpan(err) }()

	// Copy the limit, so the caller's request is not modified
	if req.Limit != nil {
		req.Limit = types.Ptr(*req.Limit)
	}

	// Filtering by rotation needs the latest passphrase version
	pool := self.PoolConn
	if req.Rotate != nil {
		_, latestPV := self.passphrases.Get(0)
		if latestPV == 0 {
			return nil, auth.ErrServiceUnavailable.With("no encryption passphrase configured for credentials")
		}
		pool = pool.With("latestpv", latestPV).(pg.PoolConn)
	}

	// List the credentials. Selecting sets the limit used on the request,
	// which is returned, clamped to the number of credentials available.
	var result schema.CredentialList
	if err := pool.List(ctx, &result, &req); err != nil {
		return nil, dbErr(err)
	} else {
		result.CredentialListRequest = req
		result.OffsetLimit.Clamp(result.Count)
	}

	// Return success
	return types.Ptr(result), nil
}
