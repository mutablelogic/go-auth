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
	cert "github.com/mutablelogic/go-auth/cert/cert"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	schema "github.com/mutablelogic/go-auth/cert/schema"
	test "github.com/mutablelogic/go-auth/cert/test"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

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
	test.Main(m, nil)
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

func Test_manager_shared(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// The shared manager has the test root, so can create a CA
	m, ctx := test.Begin(t)
	require.NotEmpty(test.Schema())

	var root cert.Certificate
	require.NoError(m.Get(ctx, (*schema.Certificate)(&root), schema.CertName(cert.RootCertName)))
	assert.True(root.IsRoot())
	require.NotNil(root.Subject)
	assert.Equal(test.RootCommonName, types.Value(root.Subject.CommonName))

	ca, err := m.CreateCA(ctx, cert.CreateCertRequest{Name: "shared_ca"})
	require.NoError(err)
	assert.Equal(cert.RootCertName, ca.Signer.Name)
}

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

		// Without a schema, it's "cert", which is dropped afterwards
		m, err := manager.New(context.Background(), test.Pool())
		require.NoError(err)
		require.NotNil(m)
		t.Cleanup(func() {
			assert.NoError(pg.SchemaDrop(context.Background(), test.Pool(), "cert"))
		})

		exists, err := pg.SchemaExists(context.Background(), m, "cert")
		require.NoError(err)
		assert.True(exists)

		assertSchemaObjects(t, m, "cert")
	})

	t.Run("NewCustomSchema", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		schemaName := test.IsolatedSchema(t)
		m := test.SchemaManager(t, schemaName)
		require.NotNil(m)

		exists, err := pg.SchemaExists(context.Background(), m, schemaName)
		require.NoError(err)
		assert.True(exists)

		assertSchemaObjects(t, m, schemaName)
	})

	t.Run("BootstrapIsIdempotent", func(t *testing.T) {
		require := require.New(t)

		schemaName := test.IsolatedSchema(t)
		m1 := test.SchemaManager(t, schemaName)
		require.NotNil(m1)

		m2 := test.SchemaManager(t, schemaName)
		require.NotNil(m2)

		assertSchemaObjects(t, m2, schemaName)
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

		m := test.IsolatedManager(t, manager.WithPassphrase(5, "root-secret-5"), manager.WithRoot(pemValue.String()))
		require.NotNil(m)

		var storedRoot cert.Certificate
		require.NoError(m.Get(context.Background(), (*schema.Certificate)(&storedRoot), schema.CertName(cert.RootCertName)))
		assert.Equal(cert.RootCertName, storedRoot.Name)
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

		var pemValue bytes.Buffer
		require.NoError(sourceRoot.Write(&pemValue))
		require.NoError(sourceRoot.WritePrivateKey(&pemValue))

		m, err := test.NewSchemaManager(test.IsolatedSchema(t), manager.WithRoot(pemValue.String()))
		require.Error(err)
		assert.Nil(m)
		assert.EqualError(err, "root certificate storage passphrase is required")
	})

	t.Run("DuplicateSubjectInsertReusesExistingRow", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		schemaName := test.IsolatedSchema(t)
		m := test.SchemaManager(t, schemaName)
		meta := cert.SubjectMeta{
			Org:           types.Ptr("Example Org"),
			Unit:          types.Ptr("Security"),
			Country:       types.Ptr("US"),
			City:          types.Ptr("San Francisco"),
			State:         types.Ptr("California"),
			StreetAddress: types.Ptr("1 Example Way"),
			PostalCode:    types.Ptr("94105"),
		}

		var first cert.Subject
		require.NoError(m.Insert(context.Background(), (*schema.Subject)(&first), schema.SubjectMeta(meta)))

		var second cert.Subject
		require.NoError(m.Insert(context.Background(), (*schema.Subject)(&second), schema.SubjectMeta(meta)))

		assert.Equal(first.ID, second.ID)
		assert.Equal(first.SubjectMeta, second.SubjectMeta)

		var count countResult
		require.NoError(m.Get(context.Background(), &count, subjectCountSelector{Schema: schemaName}))
		assert.Equal(uint64(1), count.Value)
	})
}
