package schema

import (
	"testing"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_meta_001(t *testing.T) {
	t.Run("MetaInsertExpr", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		meta, err := metaInsertExpr(map[string]any{
			"team":   "auth",
			"region": nil,
			"admin":  true,
		})
		require.NoError(err)
		assert.Equal(map[string]any{
			"admin": true,
			"team":  "auth",
		}, meta)

		_, err = metaInsertExpr(map[string]any{"bad key": true})
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("MetaPatchExprValidation", func(t *testing.T) {
		assert := assert.New(t)
		bind := pg.NewBind()

		_, err := metaPatchExpr(bind, "meta", "meta", map[string]any{"bad key": true})
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})
}
