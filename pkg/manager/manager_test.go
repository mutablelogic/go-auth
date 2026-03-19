package manager_test

import (
	"context"
	"testing"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	pg "github.com/mutablelogic/go-pg"
	test "github.com/mutablelogic/go-pg/pkg/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var conn test.Conn

///////////////////////////////////////////////////////////////////////////////
// TEST MAIN

func TestMain(m *testing.M) {
	test.Main(m, &conn)
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS

func newTestManager(t *testing.T) *manager.Manager {
	t.Helper()
	return newTestManagerWithOpts(t)
}

func newTestManagerWithOpts(t *testing.T, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	// Create a new Manager with the test connection and default schema.
	m, err := manager.New(context.Background(), c, opts...)
	if err != nil {
		t.Fatal(err)
	}

	// Wipe users (cascades to identity) between tests.
	if err := m.Exec(context.Background(), "TRUNCATE auth.user CASCADE"); err != nil {
		t.Fatal(err)
	}
	return m
}

func newCustomSchemaManager(t *testing.T, schemaName string) *manager.Manager {
	t.Helper()
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })
	t.Cleanup(func() {
		require.NoError(t, pg.SchemaDrop(context.Background(), c, schemaName))
	})

	m, err := manager.New(context.Background(), c, manager.WithSchema(schemaName))
	require.NoError(t, err)

	return m
}

///////////////////////////////////////////////////////////////////////////////
// TESTS

func Test_manager_001(t *testing.T) {
	t.Run("NewNilPool", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m, err := manager.New(context.Background(), nil)

		require.Error(err)
		assert.Nil(m)
		assert.EqualError(err, "pool is required")
	})

	t.Run("NewDefaultSchema", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		require.NotNil(m)

		exists, err := pg.SchemaExists(context.Background(), m, "auth")
		require.NoError(err)
		assert.True(exists)

		err = m.Exec(context.Background(), `TRUNCATE auth.user CASCADE`)
		assert.NoError(err)
	})

	t.Run("NewCustomSchema", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newCustomSchemaManager(t, "auth_test_custom")
		require.NotNil(m)

		exists, err := pg.SchemaExists(context.Background(), m, "auth_test_custom")
		require.NoError(err)
		assert.True(exists)

		err = m.Exec(context.Background(), `TRUNCATE auth_test_custom.user CASCADE`)
		assert.NoError(err)
	})
}
