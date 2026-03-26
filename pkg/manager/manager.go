package manager

import (
	"context"
	"fmt"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
	pg "github.com/mutablelogic/go-pg"
	broadcaster "github.com/mutablelogic/go-pg/pkg/broadcaster"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Manager wraps a database connection pool scoped to the application schema.
type Manager struct {
	opt
	pg.PoolConn
	notifications broadcaster.Broadcaster
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New creates a Manager, ensures the schema exists, and bootstraps all
// database objects from the embedded objects.sql. If schemaName is empty
// the default schema is used.
func New(ctx context.Context, pool pg.PoolConn, opts ...Opt) (*Manager, error) {
	// Set default values
	self := new(Manager)
	self.defaults()

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
	if err := bootstrap(ctx, pool, self.schema, self.channel != ""); err != nil {
		return nil, err
	} else {
		self.PoolConn = pool
	}

	// Set up notifications of table change if requested
	if self.channel != "" {
		if notifications, err := broadcaster.NewBroadcaster(pool, self.channel); err != nil {
			return nil, err
		} else {
			self.notifications = notifications
		}
	}

	// Return the manager
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// AuthConfig returns the shareable upstream provider configuration exposed by
// /auth/config. The client secret remains server-side.
func (m *Manager) AuthConfig() (schema.PublicClientConfigurations, error) {
	if len(m.oauth) == 0 {
		return nil, auth.ErrNotFound.With("oauth clients are not configured")
	}
	return m.oauth.Public(), nil
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
