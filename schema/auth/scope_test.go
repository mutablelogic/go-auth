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

package schema

import (
	"net/url"
	"strings"
	"testing"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_scope_001(t *testing.T) {
	t.Run("NormalizeScopes", func(t *testing.T) {
		assert := assert.New(t)
		assert.Equal([]string{"read", "write", "admin"}, normalizeScopes([]string{" read ", "", "write", "   ", "admin "}))
	})

	t.Run("ScopeListRequestQuery", func(t *testing.T) {
		assert := assert.New(t)

		limit := uint64(25)
		values := (ScopeListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 3, Limit: &limit},
			Q:           " profile ",
		}).Query()

		assert.Equal(url.Values{
			"offset": {"3"},
			"limit":  {"25"},
			"q":      {"profile"},
		}, values)

		assert.Contains((ScopeList{Body: []string{"profile"}}).String(), "profile")
		assert.Contains((ScopeListRequest{Q: "profile"}).String(), "profile")
	})

	t.Run("ScopeListRequestSelect", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		limit := uint64(250)
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := (ScopeListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 3, Limit: &limit},
			Q:           "read",
		}).Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.False(strings.Contains(query, "LIMIT"))
		assert.False(strings.Contains(query, "OFFSET"))
		assert.Equal("%read%", bind.Get("q"))
		assert.Equal(`WHERE scope IS NOT NULL AND scope LIKE @q ESCAPE E'\\'`, bind.Get("where"))
		assert.Equal("ORDER BY scope ASC", bind.Get("orderby"))
		assert.Equal("LIMIT 100 OFFSET 3", bind.Get("offsetlimit"))

		bind = pg.NewBind("schema", DefaultSchema)
		query, err = (ScopeListRequest{Q: `read%_\\path`}).Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal(`%read\\%\\_\\\\path%`, bind.Get("q"))
		assert.Equal(`WHERE scope IS NOT NULL AND scope LIKE @q ESCAPE E'\\'`, bind.Get("where"))

		bind = pg.NewBind("schema", DefaultSchema)
		query, err = (ScopeListRequest{}).Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.False(strings.Contains(query, "LIMIT"))
		assert.False(strings.Contains(query, "OFFSET"))
		assert.Equal("WHERE scope IS NOT NULL", bind.Get("where"))
		assert.Equal("ORDER BY scope ASC", bind.Get("orderby"))
		assert.Equal("LIMIT 100", bind.Get("offsetlimit"))

		_, err = (ScopeListRequest{}).Select(pg.NewBind(), pg.Get)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("ScopeListScan", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		list := ScopeList{OffsetLimit: pg.OffsetLimit{Limit: ptrUint64(10)}}
		require.NoError(list.Scan(mockRow{values: []any{"admin.all"}}))
		require.NoError(list.Scan(mockRow{values: []any{"profile.read"}}))
		require.NoError(list.Scan(mockRow{values: []any{"user.read"}}))
		require.NoError(list.ScanCount(mockRow{values: []any{uint(3)}}))
		assert.Equal(uint(3), list.Count)
		assert.Equal([]string{"admin.all", "profile.read", "user.read"}, list.Body)
	})
}
