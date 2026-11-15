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

// Package test runs certificate manager tests against PostgreSQL in a
// container: the manager's own tests, and the tests of what's built on it.
package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	pg "github.com/mutablelogic/go-pg"
	test "github.com/mutablelogic/go-pg/pkg/test"
)

///////////////////////////////////////////////////////////////////////////////
// CONSTANTS

const (
	// PassphraseVersion and Passphrase are registered with the shared
	// manager, so that private keys can be encrypted
	PassphraseVersion = 1
	Passphrase        = "test passphrase"

	// RootCommonName and RootOrganization are the shared manager's root
	// certificate's subject
	RootCommonName   = "Test Root CA"
	RootOrganization = "Test"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var (
	shared      *manager.Manager
	sharedPool  pg.PoolConn
	testCancels sync.Map // map[*testing.T]context.CancelFunc

	// Database schema for the shared manager, which is dropped after the
	// tests have run
	sharedSchema string
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// Main is the test main function for certificate manager tests. It starts a
// PostgreSQL container, creates a manager on it, with the test passphrase and
// a new root certificate, and runs the tests, which get the manager with
// Begin. The setup function, when it's set, is called with the manager before
// the tests run, and the teardown it returns after.
func Main(m *testing.M, setup func(*manager.Manager) (func(), error), opts ...manager.Opt) {
	test.Main(m, func(pool pg.PoolConn) (func(), error) {
		return startManager(pool, setup, opts...)
	})
}

func startManager(pool pg.PoolConn, setup func(*manager.Manager) (func(), error), opts ...manager.Opt) (func(), error) {
	// Use a new database schema for each test process. Test packages can run
	// at the same time against the same database. Options passed by the
	// caller come afterwards, so can still set the schema.
	sharedSchema = "test_" + strings.ToLower(rand.Text())
	schemaName := sharedSchema

	// The shared manager has a root certificate, so certificate authorities
	// can be created
	_, rootPEM, err := NewRoot(RootCommonName, RootOrganization)
	if err != nil {
		return nil, err
	}
	opts = append([]manager.Opt{
		manager.WithSchema(schemaName),
		manager.WithPassphrase(PassphraseVersion, Passphrase),
		manager.WithRoot(rootPEM),
	}, opts...)

	// Drop the schema after the tests have run. The manager isn't closed, as
	// it embeds the pool, which is closed by the caller.
	cleanup := func() error {
		sharedSchema = ""
		return pg.SchemaDrop(context.Background(), pool, schemaName)
	}

	mgr, err := manager.New(context.Background(), pool, opts...)
	if err != nil {
		return nil, errors.Join(err, cleanup())
	}

	teardown := func() {}
	if setup != nil {
		if teardown_, err := setup(mgr); err != nil {
			return nil, errors.Join(err, cleanup())
		} else if teardown_ != nil {
			teardown = teardown_
		}
	}

	shared = mgr
	sharedPool = pool
	return func() {
		cancelAllTestContexts()
		shared = nil
		sharedPool = nil
		teardown()
		if err := cleanup(); err != nil {
			panic(err)
		}
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// NewRoot returns a new root certificate, valid for a day, and it with its
// private key, PEM encoded, as manager.WithRoot and InsertRootCert take it
func NewRoot(commonName, organization string) (*cert.Cert, string, error) {
	root, err := cert.New(
		cert.WithCommonName(commonName),
		cert.WithOrganization(organization, ""),
		cert.WithExpiry(24*time.Hour),
		cert.WithRSAKey(2048),
		cert.WithRoot(),
	)
	if err != nil {
		return nil, "", err
	}
	var pemValue bytes.Buffer
	if err := root.Write(&pemValue); err != nil {
		return nil, "", err
	}
	if err := root.WritePrivateKey(&pemValue); err != nil {
		return nil, "", err
	}
	return root, pemValue.String(), nil
}

// Pool returns the shared test connection pool, such as for a manager of a
// test's own
func Pool() pg.PoolConn {
	return sharedPool
}

// Schema returns the database schema used by the shared test manager, for
// tests which need to refer to its tables directly
func Schema() string {
	return sharedSchema
}

// IsolatedSchema returns the name of a new, empty database schema, so that a
// test can create managers on it with its own options. The schema is dropped
// when the test ends.
func IsolatedSchema(t *testing.T) string {
	t.Helper()
	if sharedPool == nil {
		t.Fatal("test manager is not initialized; call cert/test.Main from TestMain")
	}
	pool := sharedPool
	schemaName := "test_" + strings.ToLower(rand.Text())
	t.Cleanup(func() {
		if err := pg.SchemaDrop(context.Background(), pool, schemaName); err != nil {
			t.Error(err)
		}
	})
	return schemaName
}

// IsolatedManager returns a new manager on a new, empty database schema, with
// only the options, so that a test sets its own passphrases and root, and
// can make assertions about every certificate. The schema is dropped when
// the test ends.
func IsolatedManager(t *testing.T, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	return SchemaManager(t, IsolatedSchema(t), opts...)
}

// SchemaManager returns a new manager on the schema, with the options. The
// manager isn't closed, as it shares the pool with the other managers.
func SchemaManager(t *testing.T, schemaName string, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	mgr, err := NewSchemaManager(schemaName, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

// NewSchemaManager is SchemaManager, returning its error, for tests of the
// manager's options
func NewSchemaManager(schemaName string, opts ...manager.Opt) (*manager.Manager, error) {
	if sharedPool == nil {
		return nil, errors.New("test manager is not initialized; call cert/test.Main from TestMain")
	}
	return manager.New(context.Background(), sharedPool, append([]manager.Opt{manager.WithSchema(schemaName)}, opts...)...)
}

// Begin returns the shared test manager and a per-test context, which is
// cancelled when the test ends.
func Begin(t *testing.T) (*manager.Manager, context.Context) {
	t.Helper()
	if shared == nil {
		t.Fatal("test manager is not initialized; call cert/test.Main from TestMain")
	}
	base := context.Background()
	baseCancel := func() {}
	if deadline, ok := t.Deadline(); ok {
		base, baseCancel = context.WithDeadline(base, deadline)
	}
	ctx, cancel := context.WithCancel(base)
	stop := func() {
		cancel()
		baseCancel()
	}
	testCancels.Store(t, context.CancelFunc(stop))
	t.Cleanup(func() {
		End(t)
	})
	return shared, ctx
}

// End releases the per-test context created by Begin.
func End(t *testing.T) {
	t.Helper()
	if cancelAny, ok := testCancels.LoadAndDelete(t); ok {
		if cancel, ok := cancelAny.(context.CancelFunc); ok {
			cancel()
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func cancelAllTestContexts() {
	testCancels.Range(func(key, value any) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		testCancels.Delete(key)
		return true
	})
}
