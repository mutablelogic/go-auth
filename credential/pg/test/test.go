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

package test

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	// Packages
	credential "github.com/mutablelogic/go-auth/credential/pg"
	pg "github.com/mutablelogic/go-pg"
	test "github.com/mutablelogic/go-pg/pkg/test"
)

///////////////////////////////////////////////////////////////////////////////
// CONSTANTS

const (
	// PassphraseVersion and Passphrase are registered with every test manager,
	// so that credentials can be encrypted
	PassphraseVersion = 1
	Passphrase        = "test passphrase"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var (
	shared      *credential.Manager
	sharedPool  pg.PoolConn
	testCancels sync.Map // map[*testing.T]context.CancelFunc

	// Database schema for the shared manager, which is dropped after the
	// tests have run
	sharedSchema string
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// Main is the test main function for credential manager tests. It starts a
// PostgreSQL container, creates a manager on it, with the test passphrase,
// and runs the tests, which get the manager with Begin. The setup function,
// when it's set, is called with the manager before the tests run, and the
// teardown it returns after.
func Main(m *testing.M, setup func(*credential.Manager) (func(), error), opts ...credential.Opt) {
	test.Main(m, func(pool pg.PoolConn) (func(), error) {
		return startManager(pool, setup, opts...)
	})
}

func startManager(pool pg.PoolConn, setup func(*credential.Manager) (func(), error), opts ...credential.Opt) (func(), error) {
	// Use a new database schema for each test process. Test packages can run
	// at the same time against the same database, and would otherwise share
	// credentials. Options passed by the caller come afterwards, so can still
	// set the schema.
	sharedSchema = "test_" + strings.ToLower(rand.Text())
	schemaName := sharedSchema
	opts = append(defaultOpts(schemaName), opts...)

	// Drop the schema after the tests have run. The manager isn't closed, as
	// it embeds the pool, which is closed by the caller.
	cleanup := func() error {
		sharedSchema = ""
		return pg.SchemaDrop(context.Background(), pool, schemaName)
	}

	mgr, err := credential.New(context.Background(), pool, opts...)
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

// Pool returns the shared test connection pool, such as for a connection of
// a test's own, which the manager can act on
func Pool() pg.PoolConn {
	return sharedPool
}

// Schema returns the database schema used by the shared test manager, for
// tests which need to refer to its tables directly
func Schema() string {
	return sharedSchema
}

// IsolatedSchema returns the name of a new, empty database schema, so that a
// test can create several managers on it with different options. The schema
// is dropped when the test ends.
func IsolatedSchema(t *testing.T) string {
	t.Helper()
	if sharedPool == nil {
		t.Fatal("test manager is not initialized; call credential/pg/test.Main from TestMain")
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

// IsolatedManager returns a new manager on a new, empty database schema, so
// that a test can make assertions about every credential, which it cannot do
// with the shared manager as other tests also create credentials. The schema
// is dropped when the test ends.
func IsolatedManager(t *testing.T, opts ...credential.Opt) *credential.Manager {
	t.Helper()
	return SchemaManager(t, IsolatedSchema(t), opts...)
}

// SchemaManager returns a new manager on the schema, with the test passphrase
// and the options. The manager isn't closed, as it shares the pool with the
// other managers.
func SchemaManager(t *testing.T, schemaName string, opts ...credential.Opt) *credential.Manager {
	t.Helper()
	if sharedPool == nil {
		t.Fatal("test manager is not initialized; call credential/pg/test.Main from TestMain")
	}
	mgr, err := credential.New(context.Background(), sharedPool, append(defaultOpts(schemaName), opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

// Begin returns the shared test manager and a per-test context, which is
// cancelled when the test ends.
func Begin(t *testing.T) (*credential.Manager, context.Context) {
	t.Helper()
	if shared == nil {
		t.Fatal("test manager is not initialized; call credential/pg/test.Main from TestMain")
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

// defaultOpts returns the options for a test manager on the schema
func defaultOpts(schemaName string) []credential.Opt {
	return []credential.Opt{
		credential.WithSchema(schemaName),
		credential.WithPassphrase(PassphraseVersion, Passphrase),
	}
}

func cancelAllTestContexts() {
	testCancels.Range(func(key, value any) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		testCancels.Delete(key)
		return true
	})
}
