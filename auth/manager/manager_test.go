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
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	pg "github.com/mutablelogic/go-pg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

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
// HELPERS

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

func resetManagerSchemaState(ctx context.Context, mgr *manager.Manager, schemaName string) error {
	if err := mgr.Exec(ctx, `TRUNCATE `+schemaName+`.user CASCADE`); err != nil {
		return err
	}
	if err := mgr.Exec(ctx, `
		DELETE FROM `+schemaName+`."group"
	`); err != nil {
		return err
	}
	adminDescription := "Server-managed group. Members have full access to the management API and CLI."
	adminConn := mgr.With(
		"system_group", schema.GroupSysAdmin,
		"system_description", adminDescription,
	).(pg.Conn)
	if err := adminConn.Exec(ctx, `
		INSERT INTO `+schemaName+`."group" (id, description, enabled, scopes, meta)
		VALUES (@system_group, @system_description, TRUE, '{}'::text[], '{}'::jsonb)
	`); err != nil {
		return err
	}
	for _, scope := range schema.GroupSysAdminScopes {
		if _, err := mgr.AddGroupScope(ctx, schema.GroupSysAdmin, scope); err != nil {
			return err
		}
	}

	return nil
}

func newTestManager(t *testing.T) *manager.Manager {
	t.Helper()
	require.NotNil(t, shared)
	require.NoError(t, resetManagerSchemaState(context.Background(), shared, schema.DefaultSchema))
	t.Cleanup(func() {
		if err := resetManagerSchemaState(context.Background(), shared, schema.DefaultSchema); err != nil {
			t.Error(err)
		}
	})
	return shared
}

func newCustomSchemaManager(t *testing.T, schemaName string) *manager.Manager {
	t.Helper()
	return newCustomSchemaManagerWithOpts(t, schemaName)
}

func newCustomSchemaManagerWithOpts(t *testing.T, schemaName string, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	require.NotNil(t, shared)

	ctx := context.Background()
	exists, err := pg.SchemaExists(ctx, shared, schemaName)
	require.NoError(t, err)
	if exists {
		require.NoError(t, pg.SchemaDrop(ctx, shared, schemaName))
	}
	t.Cleanup(func() {
		if err := pg.SchemaDrop(context.Background(), shared, schemaName); err != nil {
			t.Error(err)
		}
	})

	managerOpts := append([]manager.Opt{manager.WithSchema(schemaName)}, opts...)
	mgr, err := manager.New(ctx, shared.PoolConn, managerOpts...)
	require.NoError(t, err)
	return mgr
}

///////////////////////////////////////////////////////////////////////////////
// TESTS

func Test_Manager_001(t *testing.T) {
	t.Run("SharedManagerAvailable", func(t *testing.T) {
		assert := assert.New(t)
		assert.NotNil(shared)
	})

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

	t.Run("AuthConfigReturnsConfiguredProviders", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		config, err := newTestManager(t).AuthConfig()

		require.NoError(err)
		require.Len(config, 1)
		local, ok := config[schema.ProviderKeyLocal]
		require.True(ok)
		assert.Equal(DefaultIssuer, local.Issuer)
		assert.Empty(local.ClientID)
	})

	t.Run("AuthConfigRequiresProviders", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newCustomSchemaManager(t, "auth_test_auth_config_no_providers")
		config, err := m.AuthConfig()

		require.Error(err)
		assert.Nil(config)
		assert.ErrorIs(err, auth.ErrNotFound)
		assert.Contains(err.Error(), "providers are not configured")
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
