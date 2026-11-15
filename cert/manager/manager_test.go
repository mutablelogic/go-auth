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

func Test_manager_issuers(t *testing.T) {
	ctx := context.Background()
	_, pemValue, err := test.NewRoot("Example Root CA", "Example Org")
	require.NoError(t, err)
	m := test.IsolatedManager(t, manager.WithPassphrase(1, "root-secret-1"), manager.WithRoot(pemValue))

	ca1, err := m.CreateCA(ctx, cert.CreateCertRequest{Name: "ca_one"})
	require.NoError(t, err)
	ca2, err := m.CreateCA(ctx, cert.CreateCertRequest{Name: "ca_two"})
	require.NoError(t, err)
	leaf, err := m.CreateCert(ctx, cert.CreateCertRequest{Name: "leaf"}, ca1.CertKey)
	require.NoError(t, err)
	row, err := m.GetPrivateKey(ctx, leaf.CertKey)
	require.NoError(t, err)

	insert := func(row cert.CertWithPrivateKey) (cert.Certificate, error) {
		var result cert.Certificate
		err := m.Insert(ctx, (*schema.Certificate)(&result), schema.CertWithPrivateKey(row))
		return result, err
	}

	t.Run("SignerMustBeStored", func(t *testing.T) {
		orphan := *row
		orphan.CertKey = cert.CertKey{Name: "orphan", Serial: "1"}
		orphan.Signer = &cert.CertKey{Name: "missing", Serial: "1"}
		_, err := insert(orphan)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cert_issuer_check")
	})

	t.Run("NeverReplaced", func(t *testing.T) {
		// With the same issuer, another, or itself, which would be a cycle
		for _, signer := range []cert.CertKey{ca1.CertKey, ca2.CertKey, leaf.CertKey} {
			again := *row
			again.Signer = types.Ptr(signer)
			_, err := insert(again)
			assert.ErrorIs(t, pg.NormalizeError(err), pg.ErrConflict, signer.String())
		}

		// The stored certificate is unchanged
		var stored cert.Certificate
		require.NoError(t, m.Get(ctx, (*schema.Certificate)(&stored), schema.CertKey(leaf.CertKey)))
		assert.Equal(t, ca1.CertKey, types.Value(stored.Signer))
	})

	t.Run("LatestIsInsertedLast", func(t *testing.T) {
		for _, serial := range []string{"10", "9"} {
			version := *row
			version.CertKey = cert.CertKey{Name: "versioned", Serial: serial}
			_, err := insert(version)
			require.NoError(t, err)
		}
		var latest cert.Certificate
		require.NoError(t, m.Get(ctx, (*schema.Certificate)(&latest), schema.CertName("versioned")))
		assert.Equal(t, "9", latest.Serial)
	})
}

func Test_manager_review(t *testing.T) {
	ctx := context.Background()
	_, pemValue, err := test.NewRoot("Example Root CA", "Example Org")
	require.NoError(t, err)

	t.Run("RootNameIsTrimmedBeforeUpdate", func(t *testing.T) {
		m := test.IsolatedManager(t, manager.WithPassphrase(1, "root-secret-1"), manager.WithRoot(pemValue))
		var root cert.Certificate
		require.NoError(t, m.Get(ctx, (*schema.Certificate)(&root), schema.CertName(cert.RootCertName)))

		disabled := false
		_, err := m.UpdateCert(ctx, cert.CertKey{Name: " " + cert.RootCertName + " ", Serial: root.Serial}, cert.CertMeta{Enabled: &disabled})
		assert.EqualError(t, err, "Bad Request: root certificate cannot be updated")
	})

	t.Run("SameRootOnRestart", func(t *testing.T) {
		schemaName := test.IsolatedSchema(t)
		opts := []manager.Opt{manager.WithPassphrase(1, "root-secret-1"), manager.WithRoot(pemValue)}
		test.SchemaManager(t, schemaName, opts...)

		// The same root again is fine
		_, err := test.NewSchemaManager(schemaName, opts...)
		assert.NoError(t, err)

		// A different one isn't
		_, otherPEM, err := test.NewRoot("Other Root CA", "Other Org")
		require.NoError(t, err)
		_, err = test.NewSchemaManager(schemaName, manager.WithPassphrase(1, "root-secret-1"), manager.WithRoot(otherPEM))
		assert.EqualError(t, err, "Conflict: root certificate already exists")

		// The explicit import is still a conflict
		m := test.SchemaManager(t, schemaName, manager.WithPassphrase(1, "root-secret-1"))
		_, err = m.InsertRootCert(ctx, pemValue)
		assert.EqualError(t, err, "Conflict: root certificate already exists")
	})

	t.Run("LeafRenewsWithRenewedCA", func(t *testing.T) {
		m := test.IsolatedManager(t, manager.WithPassphrase(1, "root-secret-1"), manager.WithRoot(pemValue))
		ca, err := m.CreateCA(ctx, cert.CreateCertRequest{Name: "rollover_ca"})
		require.NoError(t, err)
		leaf, err := m.CreateCert(ctx, cert.CreateCertRequest{Name: "rollover_leaf", Expiry: time.Hour}, ca.CertKey)
		require.NoError(t, err)

		renewedCA, err := m.RenewCA(ctx, ca.CertKey, cert.RenewCertRequest{})
		require.NoError(t, err)

		// The leaf is still enabled, and renews with the new CA
		var current cert.Certificate
		require.NoError(t, m.Get(ctx, (*schema.Certificate)(&current), schema.CertKey(leaf.CertKey)))
		assert.True(t, types.Value(current.Enabled))

		renewed, err := m.RenewCert(ctx, leaf.CertKey, cert.RenewCertRequest{})
		require.NoError(t, err)
		assert.Equal(t, renewedCA.CertKey, types.Value(renewed.Signer))
	})

	t.Run("ConcurrentCreatesOneVersion", func(t *testing.T) {
		m := test.IsolatedManager(t, manager.WithPassphrase(1, "root-secret-1"), manager.WithRoot(pemValue))

		const n = 4
		errs := make(chan error, n)
		for range n {
			go func() {
				_, err := m.CreateCA(ctx, cert.CreateCertRequest{Name: "racing_ca"})
				errs <- err
			}()
		}
		var created int
		for range n {
			if err := <-errs; err == nil {
				created++
			} else {
				assert.EqualError(t, err, `Conflict: certificate "racing_ca" already exists`)
			}
		}
		assert.Equal(t, 1, created)

		list, err := m.ListCerts(ctx, cert.CertListRequest{})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), list.Count)
	})
}

func Test_manager_generatedRoot(t *testing.T) {
	ctx := context.Background()

	t.Run("GeneratedOnce", func(t *testing.T) {
		schemaName := test.IsolatedSchema(t)
		opts := []manager.Opt{manager.WithPassphrase(1, "root-secret-1"), manager.WithGeneratedRoot("Generated Root CA")}
		m := test.SchemaManager(t, schemaName, opts...)

		var root cert.Certificate
		require.NoError(t, m.Get(ctx, (*schema.Certificate)(&root), schema.CertName(cert.RootCertName)))
		require.NotNil(t, root.Subject)
		assert.Equal(t, "Generated Root CA", types.Value(root.Subject.CommonName))
		assert.True(t, root.IsCA)

		// It signs a CA
		ca, err := m.CreateCA(ctx, cert.CreateCertRequest{Name: "generated_ca"})
		require.NoError(t, err)
		assert.Equal(t, root.CertKey, types.Value(ca.Signer))

		// Created again, the root is kept
		again := test.SchemaManager(t, schemaName, opts...)
		var kept cert.Certificate
		require.NoError(t, again.Get(ctx, (*schema.Certificate)(&kept), schema.CertName(cert.RootCertName)))
		assert.Equal(t, root.CertKey, kept.CertKey)
	})

	t.Run("ImportedRootIsKept", func(t *testing.T) {
		_, pemValue, err := test.NewRoot("Imported Root CA", "Example Org")
		require.NoError(t, err)
		schemaName := test.IsolatedSchema(t)
		test.SchemaManager(t, schemaName, manager.WithPassphrase(1, "root-secret-1"), manager.WithRoot(pemValue))

		m := test.SchemaManager(t, schemaName, manager.WithPassphrase(1, "root-secret-1"), manager.WithGeneratedRoot("Generated Root CA"))
		var root cert.Certificate
		require.NoError(t, m.Get(ctx, (*schema.Certificate)(&root), schema.CertName(cert.RootCertName)))
		assert.Equal(t, "Imported Root CA", types.Value(root.Subject.CommonName))
	})

	t.Run("NeedsAPassphrase", func(t *testing.T) {
		_, err := test.NewSchemaManager(test.IsolatedSchema(t), manager.WithGeneratedRoot("Generated Root CA"))
		assert.EqualError(t, err, "root certificate storage passphrase is required")
		_, err = test.NewSchemaManager(test.IsolatedSchema(t), manager.WithGeneratedRoot(" "))
		assert.Error(t, err)
	})

	t.Run("ImportNeedsASelfSignedCA", func(t *testing.T) {
		// A CA which another signed isn't a root
		root, _, err := test.NewRoot("Example Root CA", "Example Org")
		require.NoError(t, err)
		intermediate, err := cert.New(cert.WithCommonName("Intermediate"), cert.WithRSAKey(2048), cert.WithExpiry(time.Hour), cert.WithCA(), cert.WithSigner(root))
		require.NoError(t, err)
		var pemValue bytes.Buffer
		require.NoError(t, intermediate.Write(&pemValue))
		require.NoError(t, intermediate.WritePrivateKey(&pemValue))
		_, err = test.NewSchemaManager(test.IsolatedSchema(t), manager.WithPassphrase(1, "root-secret-1"), manager.WithRoot(pemValue.String()))
		assert.EqualError(t, err, "root certificate must be a self-signed certificate authority")
	})
}
