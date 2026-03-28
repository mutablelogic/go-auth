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

package ldap

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestLDAPConnectionLifecycleIntegration(t *testing.T) {
	forEachLDAPIntegrationServer(t, func(t *testing.T, _ context.Context, _ ldapIntegrationServer, manager *Manager) {
		assert.NotEmpty(t, manager.Host())
		assert.NotZero(t, manager.Port())
		assert.NotEmpty(t, manager.User())

		whoami, err := manager.WhoAmI()
		require.NoError(t, err)
		assert.NotEmpty(t, whoami)

		require.NoError(t, manager.Disconnect())

		_, err = manager.WhoAmI()
		require.Error(t, err)
		assert.ErrorIs(t, err, httpresponse.ErrGatewayError)

		require.NoError(t, manager.Connect())

		whoami, err = manager.WhoAmI()
		require.NoError(t, err)
		assert.NotEmpty(t, whoami)
	})
}

func TestLDAPRunIntegration(t *testing.T) {
	forEachLDAPIntegrationServer(t, func(t *testing.T, ctx context.Context, server ldapIntegrationServer, manager *Manager) {
		requireLDAPIntegrationSchema(t, server)

		manager.users.ObjectClass = nil
		manager.groups.ObjectClass = nil
		manager.discoveryOnce = sync.Once{}

		require.NoError(t, manager.Disconnect())

		runCtx, cancel := context.WithCancel(ctx)
		errCh := make(chan error, 1)
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))

		go func() {
			errCh <- manager.Run(runCtx, logger)
		}()

		deadline := time.Now().Add(server.ConnectTimeout)
		ready := false
		for time.Now().Before(deadline) {
			manager.Lock()
			connected := manager.conn != nil
			userClasses := len(manager.users.ObjectClass)
			groupClasses := len(manager.groups.ObjectClass)
			manager.Unlock()

			if connected && userClasses > 0 && groupClasses > 0 {
				ready = true
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		require.True(t, ready, "run loop did not reconnect and discover schema in time")

		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for run loop to exit")
		}

		manager.Lock()
		defer manager.Unlock()
		assert.Nil(t, manager.conn)
	})
}
