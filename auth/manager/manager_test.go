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

package manager_test

import (
	"context"
	"strings"
	"testing"

	// Packages
	manager "github.com/mutablelogic/go-auth/auth/manager"
	authtest "github.com/mutablelogic/go-auth/auth/test"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var conn authtest.Conn

type boolResult struct {
	Value bool
}

type functionExistsSelector struct {
	Schema string
	Name   string
}

type triggerExistsSelector struct {
	Schema string
	Table  string
	Name   string
}

type stringResult struct {
	Value string
}

type functionDefinitionSelector struct {
	Schema string
	Name   string
}

///////////////////////////////////////////////////////////////////////////////
// TEST MAIN

func TestMain(m *testing.M) {
	authtest.Main(m, &conn)
}

func (result *boolResult) Scan(row pg.Row) error {
	return row.Scan(&result.Value)
}

func (result *stringResult) Scan(row pg.Row) error {
	return row.Scan(&result.Value)
}

func (selector functionExistsSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("schema", selector.Schema)
	bind.Set("name", selector.Name)
	return `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_proc AS proc
			JOIN pg_catalog.pg_namespace AS ns ON ns.oid = proc.pronamespace
			WHERE ns.nspname = @schema
			  AND proc.proname = @name
		)
	`, nil
}

func (selector triggerExistsSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("schema", selector.Schema)
	bind.Set("table", selector.Table)
	bind.Set("name", selector.Name)
	return `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_trigger AS trigger
			JOIN pg_catalog.pg_class AS class ON class.oid = trigger.tgrelid
			JOIN pg_catalog.pg_namespace AS ns ON ns.oid = class.relnamespace
			WHERE ns.nspname = @schema
			  AND class.relname = @table
			  AND trigger.tgname = @name
			  AND NOT trigger.tgisinternal
		)
	`, nil
}

func (selector functionDefinitionSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("schema", selector.Schema)
	bind.Set("name", selector.Name)
	return `
		SELECT pg_catalog.pg_get_functiondef(proc.oid)
		FROM pg_catalog.pg_proc AS proc
		JOIN pg_catalog.pg_namespace AS ns ON ns.oid = proc.pronamespace
		WHERE ns.nspname = @schema
		  AND proc.proname = @name
	`, nil
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS

func newTestManager(t *testing.T) *manager.Manager {
	t.Helper()
	return newTestManagerWithOpts(t)
}

func newTestManagerWithOpts(t *testing.T, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	return authtest.NewManager(t, &conn,
		authtest.WithSchema("auth"),
		authtest.WithoutLocalProvider(),
		authtest.WithManagerOptions(opts...),
	).Manager
}

func newCustomSchemaManager(t *testing.T, schemaName string) *manager.Manager {
	t.Helper()
	return newCustomSchemaManagerWithOpts(t, schemaName)
}

func newCustomSchemaManagerWithOpts(t *testing.T, schemaName string, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	return authtest.NewManager(t, &conn,
		authtest.WithSchema(schemaName),
		authtest.WithoutLocalProvider(),
		authtest.WithManagerOptions(opts...),
	).Manager
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

	t.Run("BootstrapSkipsTableChangeNotificationsByDefault", func(t *testing.T) {
		require := require.New(t)

		assertNotificationsAbsent := func(schemaName string, m *manager.Manager) {
			t.Helper()

			var exists boolResult
			require.NoError(m.Get(context.Background(), &exists, functionExistsSelector{
				Schema: schemaName,
				Name:   "notify_table",
			}))
			require.False(exists.Value)

			fixtures := []struct {
				table   string
				trigger string
			}{
				{table: "user", trigger: "user_table_changes_notify"},
				{table: "identity", trigger: "identity_table_changes_notify"},
				{table: "session", trigger: "session_table_changes_notify"},
				{table: "group", trigger: "group_table_changes_notify"},
				{table: "user_group", trigger: "user_group_table_changes_notify"},
			}

			for _, fixture := range fixtures {
				exists = boolResult{}
				require.NoError(m.Get(context.Background(), &exists, triggerExistsSelector{
					Schema: schemaName,
					Table:  fixture.table,
					Name:   fixture.trigger,
				}))
				require.False(exists.Value, fixture.trigger)
			}
		}

		assertNotificationsAbsent("auth", newTestManager(t))
		assertNotificationsAbsent("auth_test_no_notify", newCustomSchemaManager(t, "auth_test_no_notify"))
	})

	t.Run("BootstrapTableChangeNotifications", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		assertNotifications := func(schemaName, channel string, m *manager.Manager) {
			t.Helper()

			var exists boolResult
			require.NoError(m.Get(context.Background(), &exists, functionExistsSelector{
				Schema: schemaName,
				Name:   "notify_table",
			}))
			require.True(exists.Value)

			var definition stringResult
			require.NoError(m.Get(context.Background(), &definition, functionDefinitionSelector{
				Schema: schemaName,
				Name:   "notify_table",
			}))
			assert.True(strings.Contains(definition.Value, "pg_notify("))
			assert.Contains(definition.Value, channel)

			fixtures := []struct {
				table   string
				trigger string
			}{
				{table: "user", trigger: "user_table_changes_notify"},
				{table: "identity", trigger: "identity_table_changes_notify"},
				{table: "session", trigger: "session_table_changes_notify"},
				{table: "group", trigger: "group_table_changes_notify"},
				{table: "user_group", trigger: "user_group_table_changes_notify"},
			}

			for _, fixture := range fixtures {
				exists = boolResult{}
				require.NoError(m.Get(context.Background(), &exists, triggerExistsSelector{
					Schema: schemaName,
					Table:  fixture.table,
					Name:   fixture.trigger,
				}))
				require.True(exists.Value, fixture.trigger)
			}
		}

		assertNotifications(
			"auth_test_notify",
			"backend.table_change",
			newCustomSchemaManagerWithOpts(t, "auth_test_notify", manager.WithNotificationChannel("backend.table_change")),
		)
	})
}
