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
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_user_group_schema_001(t *testing.T) {
	t.Run("UserGroupListRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		user := UserID(uuid.New())
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := (UserGroupListRequest{User: user}).Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal(user, bind.Get("user"))

		deleteBind := pg.NewBind("schema", DefaultSchema)
		query, err = (UserGroupListRequest{User: user}).Select(deleteBind, pg.Delete)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal(user, deleteBind.Get("user"))

		_, err = (UserGroupListRequest{User: user}).Select(pg.NewBind(), pg.Get)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("UserGroupInsert", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		user := UserID(uuid.New())
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := (UserGroupInsert{User: user, Groups: []string{"admins", "staff"}}).Insert(bind)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal(user, bind.Get("user"))
		assert.Equal([]string{"admins", "staff"}, bind.Get("groups"))

		err = (UserGroupInsert{}).Update(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("UserGroupListScan", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var list UserGroupList
		require.NoError(list.Scan(mockRow{values: []any{"admins"}}))
		require.NoError(list.Scan(mockRow{values: []any{"staff"}}))
		assert.Equal(UserGroupList{"admins", "staff"}, list)
	})
}
