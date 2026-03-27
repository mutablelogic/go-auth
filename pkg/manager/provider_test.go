package manager_test

import (
	"testing"

	manager "github.com/djthorpe/go-auth/pkg/manager"
	schema "github.com/djthorpe/go-auth/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestProviderAccessors(t *testing.T) {
	mgr := newTestManagerWithOpts(t, manager.WithProvider(mustLocalProvider(t, "https://issuer.example.test/api")))

	provider, err := mgr.Provider(schema.OAuthClientKeyLocal)
	require.NoError(t, err)
	assert.Equal(t, schema.OAuthClientKeyLocal, provider.Key())

	handlers := mgr.HTTPHandlers()
	require.Len(t, handlers, 1)
	assert.Equal(t, "auth/provider/local", handlers[0].Path)
	assert.NotNil(t, handlers[0].Handler)
	assert.NotNil(t, handlers[0].Spec)

	path, err := mgr.ProviderPath(schema.OAuthClientKeyLocal)
	require.NoError(t, err)
	assert.Equal(t, "auth/provider/local", path)
}

func TestProviderMissing(t *testing.T) {
	mgr := newTestManager(t)

	_, err := mgr.Provider(schema.OAuthClientKeyLocal)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported provider "local"`)
}
