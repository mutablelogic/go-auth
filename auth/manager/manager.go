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
	"fmt"
	"strings"
	"sync"

	// Packages
	cache "github.com/mutablelogic/go-auth/auth/cache"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	broadcaster "github.com/mutablelogic/go-pg/pkg/broadcaster"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Manager wraps a database connection pool scoped to the application schema.
type Manager struct {
	sync.Mutex
	opt
	pg.PoolConn
	notifications broadcaster.Broadcaster
	keycache      cache.Cache[schema.KeyID, schema.UserID, schema.UserInfo]
	sessioncache  cache.Cache[schema.SessionID, schema.UserID, schema.UserInfo]
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New creates a Manager, ensures the schema exists, and bootstraps all
// database objects from the embedded objects.sql. If schemaName is empty
// the default schema is used.
func New(ctx context.Context, pool pg.PoolConn, name, version string, opts ...Opt) (*Manager, error) {
	// Set default values
	self := new(Manager)
	self.defaults(name, version)

	// Check arguments
	if pool == nil {
		return nil, fmt.Errorf("pool is required")
	}

	// Apply options
	if err := self.apply(opts...); err != nil {
		return nil, err
	}

	// Parse and register named queries so bind.Query(...) can resolve them.
	queries, err := pg.NewQueries(strings.NewReader(schema.Queries))
	if err != nil {
		return nil, fmt.Errorf("parse queries.sql: %w", err)
	} else {
		pool = pool.WithQueries(queries).With("schema", self.schema).(pg.PoolConn)
		if self.channel != "" {
			pool = pool.With("channel", self.channel).(pg.PoolConn)
		}
	}

	// Create objects in the database schema. This is not done in a transaction
	bootstrapCtx, endBootstrapSpan := otel.StartSpan(self.tracer, ctx, "manager.bootstrap",
		attribute.String("schema", self.schema),
		attribute.Bool("notifications", self.channel != ""),
	)
	if err := bootstrap(bootstrapCtx, pool.With("system_group", schema.GroupSysAdmin), self.schema, self.channel != ""); err != nil {
		endBootstrapSpan(err)
		return nil, err
	} else {
		endBootstrapSpan(nil)
		self.PoolConn = pool
	}

	// Seed scopes into system groups. AddGroupScope is idempotent so safe to
	// run on every startup.
	for _, scope := range schema.GroupSysAdminScopes {
		if _, err := self.AddGroupScope(ctx, schema.GroupSysAdmin, scope); err != nil {
			return nil, fmt.Errorf("seed %s scope %q: %w", schema.GroupSysAdmin, scope, err)
		}
	}

	// Initialize caches for API keys and sessions
	self.keycache = cache.New[schema.KeyID, schema.UserID, schema.UserInfo](DefaultCacheSize)
	self.sessioncache = cache.New[schema.SessionID, schema.UserID, schema.UserInfo](DefaultCacheSize)

	// Return the manager
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// Name returns the manager name
func (m *Manager) Name() string {
	return m.name
}

// Version returns the manager version.
func (m *Manager) Version() string {
	return m.version
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func bootstrap(ctx context.Context, conn pg.Conn, schemaName string, includeNotifications bool) error {
	// Get all objects
	objects, err := pg.NewQueries(strings.NewReader(schema.Objects))
	if err != nil {
		return fmt.Errorf("parse objects.sql: %w", err)
	}

	// Create the schema
	if err := pg.SchemaCreate(ctx, conn, schemaName); err != nil {
		return fmt.Errorf("create schema %q: %w", schemaName, err)
	}

	// Create all objects - not in a transaction
	for _, key := range objects.Keys() {
		if !includeNotifications && strings.HasPrefix(key, "auth.notify.") {
			continue
		}
		if err := conn.Exec(ctx, objects.Query(key)); err != nil {
			return fmt.Errorf("create object %q: %w", key, err)
		}
	}

	// Return success
	return nil
}

func (m *Manager) closeNotifications() error {
	if m == nil || m.notifications == nil {
		return nil
	}
	err := m.notifications.Close()
	m.notifications = nil
	return err
}
