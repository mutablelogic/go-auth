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
	"bytes"
	"context"
	"testing"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/pkg/cert"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	schema "github.com/mutablelogic/go-auth/cert/schema"
	pg "github.com/mutablelogic/go-pg"
	test "github.com/mutablelogic/go-pg/pkg/test"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var conn test.Conn

type boolResult struct {
	Value bool
}

type countResult struct {
	Value uint64
}

type tableExistsSelector struct {
	Schema string
	Name   string
}

type indexExistsSelector struct {
	Schema string
	Name   string
}

type subjectCountSelector struct {
	Schema string
}

///////////////////////////////////////////////////////////////////////////////
// TEST MAIN

func TestMain(m *testing.M) {
	test.Main(m, &conn)
}

func (result *boolResult) Scan(row pg.Row) error {
	return row.Scan(&result.Value)
}

func (result *countResult) Scan(row pg.Row) error {
	return row.Scan(&result.Value)
}

func (selector tableExistsSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("schema", selector.Schema)
	bind.Set("name", selector.Name)
	return `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables AS tables
			WHERE tables.table_schema = @schema
			  AND tables.table_name = @name
		)
	`, nil
}

func (selector indexExistsSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("schema", selector.Schema)
	bind.Set("name", selector.Name)
	return `
		SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_indexes AS indexes
			WHERE indexes.schemaname = @schema
			  AND indexes.indexname = @name
		)
	`, nil
}

func (selector subjectCountSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("schema", selector.Schema)
	return `
		SELECT COUNT(*)
		FROM ${"schema"}."subject"
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
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	m, err := manager.New(context.Background(), c, opts...)
	require.NoError(t, err)
	require.NoError(t, m.Exec(context.Background(), `TRUNCATE cert.subject CASCADE`))

	return m
}

func newCustomSchemaManager(t *testing.T, schemaName string) *manager.Manager {
	t.Helper()
	return newCustomSchemaManagerWithOpts(t, schemaName)
}

func newCustomSchemaManagerWithOpts(t *testing.T, schemaName string, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })
	t.Cleanup(func() {
		require.NoError(t, pg.SchemaDrop(context.Background(), c, schemaName))
	})

	baseOpts := append([]manager.Opt{manager.WithSchema(schemaName)}, opts...)
	m, err := manager.New(context.Background(), c, baseOpts...)
	require.NoError(t, err)

	return m
}

func assertSchemaObjects(t *testing.T, m *manager.Manager, schemaName string) {
	t.Helper()
	require := require.New(t)

	fixtures := []tableExistsSelector{
		{Schema: schemaName, Name: "subject"},
		{Schema: schemaName, Name: "cert"},
	}
	for _, fixture := range fixtures {
		var exists boolResult
		require.NoError(m.Get(context.Background(), &exists, fixture))
		require.True(exists.Value, fixture.Name)
	}

	indexes := []indexExistsSelector{
		{Schema: schemaName, Name: "cert_name_serial_idx"},
		{Schema: schemaName, Name: "cert_name_idx"},
		{Schema: schemaName, Name: "cert_issuer_idx"},
	}
	for _, fixture := range indexes {
		var exists boolResult
		require.NoError(m.Get(context.Background(), &exists, fixture))
		require.True(exists.Value, fixture.Name)
	}
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

		exists, err := pg.SchemaExists(context.Background(), m, "cert")
		require.NoError(err)
		assert.True(exists)

		assertSchemaObjects(t, m, "cert")
		err = m.Exec(context.Background(), `TRUNCATE cert.subject CASCADE`)
		assert.NoError(err)
	})

	t.Run("NewCustomSchema", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newCustomSchemaManager(t, "cert_test_custom")
		require.NotNil(m)

		exists, err := pg.SchemaExists(context.Background(), m, "cert_test_custom")
		require.NoError(err)
		assert.True(exists)

		assertSchemaObjects(t, m, "cert_test_custom")
		err = m.Exec(context.Background(), `TRUNCATE cert_test_custom.subject CASCADE`)
		assert.NoError(err)
	})

	t.Run("BootstrapIsIdempotent", func(t *testing.T) {
		require := require.New(t)

		c := conn.Begin(t)
		defer c.Close()

		m1, err := manager.New(context.Background(), c, manager.WithSchema("cert_test_idempotent"))
		require.NoError(err)
		require.NotNil(m1)

		m2, err := manager.New(context.Background(), c, manager.WithSchema("cert_test_idempotent"))
		require.NoError(err)
		require.NotNil(m2)

		assertSchemaObjects(t, m2, "cert_test_idempotent")
		require.NoError(pg.SchemaDrop(context.Background(), c, "cert_test_idempotent"))
	})

	t.Run("NewWithRootImportsRootCert", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		sourceRoot, err := cert.New(
			cert.WithCommonName("Example Root CA"),
			cert.WithOrganization("Example Org", ""),
			cert.WithExpiry(24*time.Hour),
			cert.WithRSAKey(2048),
			cert.WithRoot(),
		)
		require.NoError(err)

		var pemValue bytes.Buffer
		require.NoError(sourceRoot.Write(&pemValue))
		require.NoError(sourceRoot.WritePrivateKey(&pemValue))

		m := newCustomSchemaManagerWithOpts(t, "cert_test_root_import", manager.WithPassphrase(5, "root-secret-5"), manager.WithRoot(pemValue.String()))
		require.NotNil(m)

		var storedRoot schema.Cert
		require.NoError(m.Get(context.Background(), &storedRoot, schema.CertName(schema.RootCertName)))
		assert.Equal(schema.RootCertName, storedRoot.Name)
		assert.NotEmpty(storedRoot.Serial)
		assert.True(storedRoot.IsCA)
		assert.True(storedRoot.IsRoot())
		require.NotNil(storedRoot.Subject)
		assert.True(types.Value(storedRoot.Enabled))
	})

	t.Run("NewWithRootRejectsWithoutPassphrase", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		sourceRoot, err := cert.New(
			cert.WithCommonName("Example Root CA"),
			cert.WithOrganization("Example Org", ""),
			cert.WithExpiry(24*time.Hour),
			cert.WithRSAKey(2048),
			cert.WithRoot(),
		)
		require.NoError(err)
		schemaName := "cert_test_root_import_no_pass"

		var pemValue bytes.Buffer
		require.NoError(sourceRoot.Write(&pemValue))
		require.NoError(sourceRoot.WritePrivateKey(&pemValue))

		c := conn.Begin(t)
		defer c.Close()
		defer func() {
			_ = pg.SchemaDrop(context.Background(), c, schemaName)
		}()

		m, err := manager.New(context.Background(), c, manager.WithSchema(schemaName), manager.WithRoot(pemValue.String()))
		require.Error(err)
		assert.Nil(m)
		assert.EqualError(err, "root certificate storage passphrase is required")
	})

	t.Run("DuplicateSubjectInsertReusesExistingRow", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		meta := schema.SubjectMeta{
			Org:           types.Ptr("Example Org"),
			Unit:          types.Ptr("Security"),
			Country:       types.Ptr("US"),
			City:          types.Ptr("San Francisco"),
			State:         types.Ptr("California"),
			StreetAddress: types.Ptr("1 Example Way"),
			PostalCode:    types.Ptr("94105"),
		}

		var first schema.Subject
		require.NoError(m.Insert(context.Background(), &first, meta))

		var second schema.Subject
		require.NoError(m.Insert(context.Background(), &second, meta))

		assert.Equal(first.ID, second.ID)
		assert.Equal(first.SubjectMeta, second.SubjectMeta)

		var count countResult
		require.NoError(m.Get(context.Background(), &count, subjectCountSelector{Schema: "cert"}))
		assert.Equal(uint64(1), count.Value)
	})
}
