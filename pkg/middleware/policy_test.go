package middleware

import (
	"testing"

	schema "github.com/djthorpe/go-auth/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_policy_001(t *testing.T) {
	t.Run("MatchUserRejectsNilUser", func(t *testing.T) {
		assert := assert.New(t)

		err := MatchScopes("auth:user:read").MatchUser(nil)

		assert.EqualError(err, "user is required")
	})

	t.Run("MatchUserAllowsUserWithRequiredScopes", func(t *testing.T) {
		require := require.New(t)

		user := &schema.User{Scopes: []string{"auth:user:read", "auth:group:write"}}

		err := MatchScopes("auth:user:read", "auth:group:write").MatchUser(user)

		require.NoError(err)
	})
}
