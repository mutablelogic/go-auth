package schema

import (
	"testing"

	// Packages
	auth "github.com/djthorpe/go-auth"
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
