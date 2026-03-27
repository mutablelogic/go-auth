package manager

import (
	"context"
	"testing"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	localprovider "github.com/djthorpe/go-auth/pkg/provider/local"
	schema "github.com/djthorpe/go-auth/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func testLocalProvider(t *testing.T) providerpkg.Provider {
	t.Helper()
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	provider, err := localprovider.New("https://issuer.example.test/api", key)
	require.NoError(t, err)
	return provider
}

func Test_opt_001(t *testing.T) {
	t.Run("ApplySkipsNil", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(options.apply(nil))
	})

	t.Run("WithProvider", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		provider := testLocalProvider(t)
		require.NoError(WithProvider(provider)(options))

		provider, ok := options.providers[schema.ProviderKeyLocal]
		require.True(ok)
		assert.Equal(schema.ProviderKeyLocal, provider.Key())

		resp, err := provider.BeginAuthorization(context.Background(), providerpkg.AuthorizationRequest{
			RedirectURL: "http://127.0.0.1:8085/callback",
			ProviderURL: "/auth/provider/local",
			State:       "state-123",
		})
		require.NoError(err)
		assert.Contains(resp.RedirectURL, "/auth/provider/local")

		assert.EqualError(WithProvider(provider)(options), `provider key "local" already configured`)
		assert.EqualError(WithProvider(nil)(options), "provider is required")
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
		assert.NoError(WithCleanup(0, 25)(options))
		assert.Equal(DefaultCleanupInterval, options.cleanupint)
		assert.Equal(25, options.cleanuplimit)
		assert.NoError(WithCleanup(time.Minute, 0)(options))
		assert.Equal(time.Minute, options.cleanupint)
		assert.Equal(DefaultCleanupLimit, options.cleanuplimit)
		assert.EqualError(WithCleanup(-time.Second, 25)(options), "cleanup interval must not be negative")
		assert.EqualError(WithCleanup(time.Minute, -1)(options), "cleanup limit must not be negative")
	})

	t.Run("Defaults", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		options.defaults()
		assert.Equal(schema.DefaultSchema, options.schema)
		assert.Empty(options.channel)
		assert.Equal(schema.DefaultSessionTTL, options.sessionttl)
		assert.Equal(DefaultCleanupInterval, options.cleanupint)
		assert.Equal(DefaultCleanupLimit, options.cleanuplimit)
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

	t.Run("WithNotificationChannel", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(WithNotificationChannel("backend.table_change")(options))
		assert.Equal("backend.table_change", options.channel)
		assert.EqualError(WithNotificationChannel("")(options), "notification channel cannot be empty")
		assert.NoError(WithNotifyChannel("compat.table_change")(options))
		assert.Equal("compat.table_change", options.channel)
	})

	t.Run("WithHooks", func(t *testing.T) {
		assert := assert.New(t)

		type testHooks struct{}
		options := new(opt)
		hooks := testHooks{}
		assert.NoError(WithHooks(hooks)(options))
		assert.Equal(hooks, options.hooks)
		assert.EqualError(WithHooks(nil)(options), "hooks are required")
	})

	t.Run("ApplyStopsOnError", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		err := options.apply(WithSchema("custom_auth"), WithProvider(nil), WithSessionTTL(time.Minute))
		assert.EqualError(err, "provider is required")
		assert.Equal("custom_auth", options.schema)
		assert.Zero(options.sessionttl)
	})
}
