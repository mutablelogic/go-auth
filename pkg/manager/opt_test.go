package manager

import (
	"context"
	"testing"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	schema "github.com/djthorpe/go-auth/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_opt_001(t *testing.T) {
	t.Run("ApplySkipsNil", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(options.apply(nil))
	})

	t.Run("WithIssuer", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(WithIssuer("https://issuer.example.test/api")(options))
		assert.Equal("https://issuer.example.test/api", options.issuer)
		assert.EqualError(WithIssuer("")(options), "issuer cannot be empty")
	})

	t.Run("WithSessionTTL", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(WithSessionTTL(15 * time.Minute)(options))
		assert.Equal(15*time.Minute, options.sessionttl)
		assert.EqualError(WithSessionTTL(0)(options), "session TTL must be positive")
	})

	t.Run("WithCleanup", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(WithCleanup(time.Minute, 25)(options))
		assert.Equal(time.Minute, options.cleanupint)
		assert.Equal(25, options.cleanuplimit)
		assert.EqualError(WithCleanup(0, 25)(options), "cleanup interval must be positive")
		assert.EqualError(WithCleanup(time.Minute, 0)(options), "cleanup limit must be positive")
	})

	t.Run("WithPrivateKey", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		key, err := authcrypto.GeneratePrivateKey()
		require.NoError(err)
		assert.NoError(WithPrivateKey(key)(options))
		assert.Same(key, options.privateKey)
		assert.EqualError(WithPrivateKey(nil)(options), "private key is required")
	})

	t.Run("WithSchema", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(WithSchema("custom_auth")(options))
		assert.Equal("custom_auth", options.schema)
		assert.EqualError(WithSchema("")(options), "schema name cannot be empty")
	})

	t.Run("WithUserHook", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		hook := func(ctx context.Context, identity schema.IdentityInsert, meta schema.UserMeta) (schema.UserMeta, error) {
			return meta, nil
		}
		assert.NoError(WithUserHook(hook)(options))
		assert.NotNil(options.userhook)
		assert.EqualError(WithUserHook(nil)(options), "user hook is required")
	})

	t.Run("ApplyStopsOnError", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		err := options.apply(WithSchema("custom_auth"), WithIssuer(""), WithSessionTTL(time.Minute))
		assert.EqualError(err, "issuer cannot be empty")
		assert.Equal("custom_auth", options.schema)
		assert.Zero(options.sessionttl)
	})
}
