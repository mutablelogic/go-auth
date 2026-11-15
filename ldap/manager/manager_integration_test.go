//go:build integration

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

package manager

import (
	"context"
	"testing"
	"time"

	// Packages
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_Integration_Connection(t *testing.T) {
	forEachServer(t, func(t *testing.T, ctx context.Context, server integrationServer, manager *Manager) {
		assert.Equal(t, "127.0.0.1", manager.Host())
		assert.NotZero(t, manager.Port())
		assert.Equal(t, server.BindDN, manager.User())

		whoami, err := manager.WhoAmI(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, whoami)

		// A second Connect checks the connection, rather than connecting
		require.NoError(t, manager.Connect(ctx))

		require.NoError(t, manager.Disconnect(ctx))
		_, err = manager.WhoAmI(ctx)
		assert.ErrorIs(t, err, httpresponse.ErrGatewayError)

		require.NoError(t, manager.Connect(ctx))
		whoami, err = manager.WhoAmI(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, whoami)
	})
}

func Test_Integration_WrongPassword(t *testing.T) {
	forEachServer(t, func(t *testing.T, ctx context.Context, server integrationServer, manager *Manager) {
		other, err := New(WithUrl(manager.url.String()), WithBaseDN(server.BaseDN), WithUser(server.BindDN), WithPassword("wrong-password"), WithSkipVerify())
		require.NoError(t, err)
		assert.ErrorIs(t, other.Connect(ctx), httpresponse.ErrNotAuthorized)
		assert.Nil(t, other.conn, "the connection is closed")
	})
}

func Test_Integration_Run(t *testing.T) {
	forEachServer(t, func(t *testing.T, ctx context.Context, server integrationServer, manager *Manager) {
		require.NoError(t, manager.Disconnect(ctx))

		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- manager.Run(runCtx, slogDiscard()) }()

		// Run connects
		connected := func() bool {
			manager.mu.Lock()
			defer manager.mu.Unlock()
			return manager.conn != nil
		}
		assert.Eventually(t, connected, server.ConnectTimeout, 100*time.Millisecond)

		// And disconnects when it's cancelled
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for Run to return")
		}
		assert.False(t, connected())
	})
}
