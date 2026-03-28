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
	"context"
	"testing"
	"time"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	schema "github.com/djthorpe/go-auth/schema/auth"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_notification_001(t *testing.T) {
	t.Run("RequiresConfiguredChannel", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		err := m.ChangeNotification(context.Background(), func(schema.ChangeNotification) {})

		require.Error(err)
		assert.ErrorIs(err, pg.ErrNotAvailable)
	})

	t.Run("RejectsNilCallback", func(t *testing.T) {
		assert := assert.New(t)

		m := newTestManagerWithOpts(t, manager.WithNotificationChannel("backend.table_change"))
		err := m.ChangeNotification(context.Background(), nil)

		assert.ErrorIs(err, pg.ErrBadParameter)
	})

	t.Run("DeliversDecodedChange", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManagerWithOpts(t, manager.WithNotificationChannel("backend.table_change"))
		changes := make(chan schema.ChangeNotification, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		require.NoError(m.ChangeNotification(ctx, func(change schema.ChangeNotification) {
			select {
			case changes <- change:
			default:
			}
		}))

		require.NoError(m.Exec(context.Background(), `
			INSERT INTO auth."group" (id, description)
			VALUES ('notification-group', 'Notification Group')
		`))

		select {
		case change := <-changes:
			assert.Equal("auth", change.Schema)
			assert.Equal("group", change.Table)
			assert.Equal("INSERT", change.Action)
		case <-ctx.Done():
			t.Fatal("timed out waiting for notification")
		}
	})

	t.Run("BroadcastsToAllSubscribers", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManagerWithOpts(t, manager.WithNotificationChannel("backend.table_change"))
		first := make(chan schema.ChangeNotification, 1)
		second := make(chan schema.ChangeNotification, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		require.NoError(m.ChangeNotification(ctx, func(change schema.ChangeNotification) {
			select {
			case first <- change:
			default:
			}
		}))
		require.NoError(m.ChangeNotification(ctx, func(change schema.ChangeNotification) {
			select {
			case second <- change:
			default:
			}
		}))

		require.NoError(m.Exec(context.Background(), `
			INSERT INTO auth."group" (id, description)
			VALUES ('notification-broadcast-group', 'Notification Broadcast Group')
		`))

		select {
		case change := <-first:
			assert.Equal("group", change.Table)
		case <-ctx.Done():
			t.Fatal("timed out waiting for first subscriber notification")
		}

		select {
		case change := <-second:
			assert.Equal("group", change.Table)
		case <-ctx.Done():
			t.Fatal("timed out waiting for second subscriber notification")
		}
	})
}
