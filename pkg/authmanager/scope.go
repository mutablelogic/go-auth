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

package manager

import (
	"context"

	// Packages
	schema "github.com/mutablelogic/go-auth/schema/auth"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) ListScopes(ctx context.Context, req schema.ScopeListRequest) (_ *schema.ScopeList, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.ListScopes", attribute.String("request", req.String()))
	defer func() { endSpan(err) }()

	result := schema.ScopeList{OffsetLimit: req.OffsetLimit}
	if err = m.PoolConn.List(ctx, &result, req); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}
