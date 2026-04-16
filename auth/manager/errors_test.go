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

package manager

import (
	"errors"
	"testing"

	// Packages
	pgx "github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	auth "github.com/mutablelogic/go-auth"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_dbErr_001(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		assert := assert.New(t)
		assert.NoError(dbErr(nil))
	})

	t.Run("AuthErrorPassthrough", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		original := auth.ErrInvalidProvider.With("bad provider")
		result := dbErr(original)

		require.Error(result)
		assert.ErrorIs(result, auth.ErrInvalidProvider)
		assert.EqualError(result, original.Error())
	})

	t.Run("NormalizeNoRowsToNotFound", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		result := dbErr(pgx.ErrNoRows)

		require.Error(result)
		assert.ErrorIs(result, auth.ErrNotFound)
		assert.Contains(result.Error(), pg.ErrNotFound.Error())
	})

	t.Run("MapNotFound", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		result := dbErr(pg.ErrNotFound.With("missing row"))

		require.Error(result)
		assert.ErrorIs(result, auth.ErrNotFound)
		assert.Contains(result.Error(), "missing row")
	})

	t.Run("MapConflict", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		result := dbErr(pg.ErrConflict.With("duplicate key"))

		require.Error(result)
		assert.ErrorIs(result, auth.ErrConflict)
		assert.Contains(result.Error(), "duplicate key")
	})

	t.Run("MapBadParameter", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		result := dbErr(pg.ErrBadParameter.With("invalid input"))

		require.Error(result)
		assert.ErrorIs(result, auth.ErrBadParameter)
		assert.Contains(result.Error(), "invalid input")
	})

	t.Run("MapNormalizedDatabaseConflict", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		result := dbErr(&pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"})

		require.Error(result)
		assert.ErrorIs(result, auth.ErrConflict)
		assert.Contains(result.Error(), "duplicate key value violates unique constraint")
	})

	t.Run("MapUnknownDatabaseErrorToInternal", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		result := dbErr(&pgconn.PgError{Code: "XX000", Message: "internal database failure"})

		require.Error(result)
		assert.ErrorIs(result, auth.ErrInternalServerError)
		assert.Contains(result.Error(), "internal database failure")
	})

	t.Run("PassthroughUnknownError", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		original := errors.New("plain error")
		result := dbErr(original)

		require.Error(result)
		assert.Same(original, result)
	})
}
