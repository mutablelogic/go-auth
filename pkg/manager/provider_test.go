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

package manager_test

import (
	"testing"

	manager "github.com/djthorpe/go-auth/pkg/manager"
	schema "github.com/djthorpe/go-auth/schema/auth"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestProviderAccessors(t *testing.T) {
	mgr := newTestManagerWithOpts(t, manager.WithProvider(mustLocalProvider(t, "https://issuer.example.test/api")))

	provider, err := mgr.Provider(schema.ProviderKeyLocal)
	require.NoError(t, err)
	assert.Equal(t, schema.ProviderKeyLocal, provider.Key())

	handlers := mgr.HTTPHandlers()
	require.Len(t, handlers, 1)
	assert.Equal(t, "auth/provider/local", handlers[0].Path)
	assert.NotNil(t, handlers[0].Handler)
	assert.NotNil(t, handlers[0].Spec)

	path, err := mgr.ProviderPath(schema.ProviderKeyLocal)
	require.NoError(t, err)
	assert.Equal(t, "auth/provider/local", path)
}

func TestProviderMissing(t *testing.T) {
	mgr := newTestManager(t)

	_, err := mgr.Provider(schema.ProviderKeyLocal)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported provider "local"`)
}
