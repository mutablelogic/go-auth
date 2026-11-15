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

package pg_test

import (
	"context"
	"fmt"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential/pg"
	test "github.com/mutablelogic/go-auth/credential/pg/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	test.Main(m, nil)
}

func TestNew(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)

	t.Run("Schema", func(t *testing.T) {
		// The credential table is created in the manager's schema
		require.NotEmpty(t, test.Schema())
		assert.NoError(t, manager.Exec(ctx, fmt.Sprintf(`SELECT 1 FROM %q."credential" LIMIT 0`, test.Schema())))
	})

	t.Run("Bootstrap", func(t *testing.T) {
		// Creating a manager on a schema which already exists succeeds
		_, err := credential.New(ctx, manager.PoolConn, credential.WithSchema(test.Schema()))
		assert.NoError(t, err)
	})

	t.Run("NoPool", func(t *testing.T) {
		_, err := credential.New(context.Background(), nil)
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("InvalidPassphrase", func(t *testing.T) {
		// Passphrases must be non-empty
		_, err := credential.New(ctx, manager.PoolConn, credential.WithSchema(test.Schema()), credential.WithPassphrase(2, ""))
		assert.Error(t, err)
	})
}

func TestIsolatedManager(t *testing.T) {
	manager := test.IsolatedManager(t)
	require.NotNil(t, manager)
	ctx := context.Background()

	// The credential table is created in the manager's own schema, which is
	// bound to its queries as "schema"
	assert.NoError(t, manager.Exec(ctx, `SELECT 1 FROM ${"schema"}."credential" LIMIT 0`))

	// The schema is not the shared manager's schema
	assert.NoError(t, manager.Exec(ctx, fmt.Sprintf(`DO $$ BEGIN IF ${'schema'} = '%s' THEN RAISE EXCEPTION 'isolated manager uses the shared schema'; END IF; END $$`, test.Schema())))
}
