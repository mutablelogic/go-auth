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
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	attribute "go.opentelemetry.io/otel/attribute"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

type Manager struct {
	opt
	pg.PoolConn
}

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New creates a new manager object
func New(ctx context.Context, pool pg.PoolConn, opts ...Opt) (_ *Manager, err error) {
	self := new(Manager)

	// Check parameters
	if pool == nil {
		return nil, auth.ErrBadParameter.With("pg pool is required")
	}

	// Apply options
	if err := self.opt.apply(opts); err != nil {
		return nil, err
	}

	// Trace creating the manager, which needs the tracer from the options
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.pg.New",
		attribute.String("schema", self.schema),
	)
	defer func() { endSpan(err) }()

	// Parse and register named queries so bind.Query(...) can resolve them.
	queries, err := pg.NewQueries(strings.NewReader(schema.Queries))
	if err != nil {
		return nil, auth.ErrInternalServerError.Withf("queries.sql: %w", err)
	} else {
		pool = pool.WithQueries(queries).With(
			"schema", self.schema,
		).(pg.PoolConn)
	}

	// Create the schema and the objects in it
	if err := bootstrap(ctx, pool, self.schema, self.channel); err != nil {
		return nil, err
	} else {
		self.PoolConn = pool
	}

	// Return success
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func bootstrap(ctx context.Context, conn pg.Conn, schemaName, channel string) error {
	// Get all objects
	objects, err := pg.NewQueries(strings.NewReader(schema.Objects))
	if err != nil {
		return auth.ErrInternalServerError.Withf("objects.sql: %w", err)
	}

	// Create the schema
	if err := pg.SchemaCreate(ctx, conn, schemaName); err != nil {
		return auth.ErrInternalServerError.Withf("create schema %q: %w", schemaName, err)
	}

	// Create all objects - not in a transaction. The trigger which notifies
	// the channel of the changes is only created with a channel, and
	// dropped without one.
	conn = conn.With("channel", channel)
	for _, key := range objects.Keys() {
		if strings.HasPrefix(key, "credential.notify_") && channel == "" {
			continue
		}
		if err := conn.Exec(ctx, objects.Query(key)); err != nil {
			return auth.ErrInternalServerError.Withf("create object %q: %w", key, err)
		}
	}
	if channel == "" {
		if err := conn.Exec(ctx, `DROP TRIGGER IF EXISTS credential_notify_trigger ON ${"schema"}."credential"`); err != nil {
			return auth.ErrInternalServerError.Withf("drop object %q: %w", "credential.notify_trigger", err)
		}
	}

	// Return success
	return nil
}
