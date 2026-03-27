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
	"database/sql"
	"strings"
	"testing"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_group_schema_001(t *testing.T) {
	t.Run("GroupInsert", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		insert := GroupInsert{
			ID: "admins",
			GroupMeta: GroupMeta{
				Description: ptrString("  Administrators  "),
				Scopes:      []string{"user.read", "user.write"},
				Meta:        map[string]any{"team": "auth"},
			},
		}
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := insert.Insert(bind)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal("admins", bind.Get("id"))
		assert.Equal("Administrators", bind.Get("description"))
		assert.Equal(true, bind.Get("enabled"))
		assert.Equal([]string{"user.read", "user.write"}, bind.Get("scopes"))
		assert.Equal(map[string]any{"team": "auth"}, bind.Get("meta"))

		normalizedBind := pg.NewBind("schema", DefaultSchema)
		_, err = (GroupInsert{
			ID: "operators",
			GroupMeta: GroupMeta{
				Scopes: []string{" user.read ", "   ", "write ", "", "  admin"},
			},
		}).Insert(normalizedBind)
		require.NoError(err)
		assert.Equal([]string{"user.read", "write", "admin"}, normalizedBind.Get("scopes"))

		blankBind := pg.NewBind("schema", DefaultSchema)
		_, err = (GroupInsert{ID: "operators"}).Insert(blankBind)
		require.NoError(err)
		assert.Nil(blankBind.Get("description"))

		hyphenBind := pg.NewBind("schema", DefaultSchema)
		_, err = (GroupInsert{ID: "power-users"}).Insert(hyphenBind)
		require.NoError(err)
		assert.Equal("power-users", hyphenBind.Get("id"))

		_, err = (GroupInsert{ID: "1invalid"}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = (GroupInsert{ID: "a" + strings.Repeat("x", 64)}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("GroupSelect", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		group := Group{ID: "admins"}
		bind := pg.NewBind()
		query, err := group.Select(bind, pg.Get)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal("admins", bind.Get("id"))

		_, err = group.Select(pg.NewBind(), pg.Update)
		require.NoError(err)
		_, err = group.Select(pg.NewBind(), pg.Delete)
		require.NoError(err)
		_, err = group.Select(pg.NewBind(), pg.None)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("GroupListRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		limit := uint64(10)
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := (GroupListRequest{OffsetLimit: pg.OffsetLimit{Offset: 3, Limit: &limit}}).Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal("", bind.Get("where"))
		assert.Equal("ORDER BY group_row.id ASC", bind.Get("orderby"))
	})

	t.Run("GroupScan", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var group Group
		err := group.Scan(mockRow{values: []any{
			"admins",
			sql.NullString{String: "Administrators", Valid: true},
			true,
			[]string{"user.read", "user.write"},
			map[string]any{"team": "auth"},
		}})
		require.NoError(err)
		assert.Equal("admins", group.ID)
		require.NotNil(group.Description)
		assert.Equal("Administrators", *group.Description)
		require.NotNil(group.Enabled)
		assert.True(*group.Enabled)
		assert.Equal([]string{"user.read", "user.write"}, group.Scopes)
		assert.Equal("auth", group.Meta["team"])

		err = group.Scan(mockRow{values: []any{
			"operators",
			nil,
			true,
			[]string{"user.read"},
			map[string]any{},
		}})
		require.NoError(err)
		assert.Equal("operators", group.ID)
		assert.Nil(group.Description)
	})

	t.Run("GroupListScanAndCount", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		list := GroupList{OffsetLimit: pg.OffsetLimit{Limit: ptrUint64(10)}}
		require.NoError(list.Scan(mockRow{values: []any{"admins", sql.NullString{String: "Administrators", Valid: true}, true, []string{"user.read"}, map[string]any{"team": "auth"}}}))
		require.NoError(list.Scan(mockRow{values: []any{"editors", sql.NullString{String: "Editors", Valid: true}, false, []string{"user.write"}, map[string]any{"team": "content"}}}))
		require.NoError(list.ScanCount(mockRow{values: []any{uint(2)}}))
		assert.Len(list.Body, 2)
		assert.Equal(uint(2), list.Count)
	})

	t.Run("GroupMetaUpdate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		enabled := false
		bind := pg.NewBind()
		err := (GroupMeta{
			Description: ptrString("  Editors  "),
			Enabled:     &enabled,
			Scopes:      []string{"user.write"},
			Meta:        map[string]any{"team": "content"},
		}).Update(bind)
		require.NoError(err)
		assert.True(bind.Has("patch"))
		assert.Equal("Editors", bind.Get("description"))
		assert.Equal(false, bind.Get("enabled"))
		assert.Equal([]string{"user.write"}, bind.Get("scopes"))
		assert.Equal("team", bind.Get("meta_key_0"))
		assert.Equal(`"content"`, bind.Get("meta_value_0"))
		assert.True(strings.Contains(bind.Get("patch").(string), "meta = "))
		assert.True(strings.Contains(bind.Get("patch").(string), "jsonb_build_object("))

		bind = pg.NewBind()
		err = (GroupMeta{Scopes: []string{" read ", " ", "write ", "", " admin"}}).Update(bind)
		require.NoError(err)
		assert.Equal([]string{"read", "write", "admin"}, bind.Get("scopes"))
		assert.Equal("scopes = @scopes", bind.Get("patch"))

		bind = pg.NewBind()
		err = (GroupMeta{Description: ptrString("  ")}).Update(bind)
		require.NoError(err)
		assert.Equal("description = NULL", bind.Get("patch"))

		bind = pg.NewBind()
		err = (GroupMeta{Meta: map[string]any{"team": nil, "admin": true}}).Update(bind)
		require.NoError(err)
		patch := bind.Get("patch").(string)
		assert.Equal("admin", bind.Get("meta_key_0"))
		assert.Equal("true", bind.Get("meta_value_0"))
		assert.Equal("team", bind.Get("meta_key_1"))
		assert.True(strings.Contains(patch, "jsonb_build_object("))
		assert.True(strings.Contains(patch, " - @meta_key_1"))

		err = (GroupMeta{}).Update(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})
}

func ptrString(value string) *string {
	return &value
}
