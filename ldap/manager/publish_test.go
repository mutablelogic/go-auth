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
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	ldapv3 "github.com/go-ldap/ldap/v3"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	changes "github.com/mutablelogic/go-server/broadcaster/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// recorder records the changes published to it
type recorder struct {
	sync.Mutex
	changes []changes.Change
}

func (r *recorder) Publish(change changes.Change) int {
	r.Lock()
	defer r.Unlock()
	r.changes = append(r.changes, change)
	return 0
}

// take returns the changes, as "table action row", with the previous row
// when there's one, in lower case, and forgets them
func (r *recorder) take(t *testing.T) []string {
	t.Helper()
	r.Lock()
	defer r.Unlock()
	var result []string
	for _, change := range r.changes {
		assert.Equal(t, schema.SchemaName, change.Schema)
		line := change.Table + " " + string(change.Action) + " " + change.Row
		if change.Data != nil {
			var data map[string]string
			require.NoError(t, json.Unmarshal(change.Data, &data))
			line += " from " + data["previous"]
		}
		result = append(result, strings.ToLower(line))
	}
	r.changes = nil
	return result
}

func Test_Changes(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		users, groups := test.OU(t, ctx, m), test.OU(t, ctx, m)
		r := new(recorder)
		published := test.Manager(t, ctx, server, manager.WithUserDN(users), manager.WithGroupDN(groups), manager.WithBroadcaster(r))
		host := strings.ToLower(strings.TrimPrefix(server.URL, "ldaps://"))
		assert.Equal(t, []string{"connection create " + host}, r.take(t))

		// Objects, and a rename, with what it was
		ou := strings.ToLower(test.OU(t, ctx, m))
		_, err := published.Create(ctx, "ou=a,"+ou, unit("a"))
		require.NoError(t, err)
		_, err = published.Update(ctx, "ou=a,"+ou, schema.Attrs{"description": {"A"}})
		require.NoError(t, err)
		_, err = published.Update(ctx, "ou=a,"+ou, schema.Attrs{"ou": {"b"}})
		require.NoError(t, err)
		_, err = published.Delete(ctx, "ou=b,"+ou)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"object create ou=a," + ou,
			"object update ou=a," + ou,
			"object update ou=b," + ou + " from ou=a," + ou,
			"object delete ou=b," + ou,
		}, normalize(r.take(t)))

		// Users, and their passwords, which change their objects
		user, err := published.CreateUser(ctx, "alice", userAttrs("alice", "first Passw0rd!"), true)
		require.NoError(t, err)
		_, err = published.ChangePassword(ctx, user.DN, schema.ObjectPasswordRequest{New: types.Ptr("second Passw0rd!")})
		require.NoError(t, err)
		naming := "uid"
		if server.ActiveDirectory {
			naming = "cn"
		}
		_, err = published.UpdateUser(ctx, "alice", schema.Attrs{naming: {"alicia"}})
		require.NoError(t, err)
		assert.Equal(t, []string{
			"user create alice",
			"object update " + strings.ToLower(user.DN),
			"user update alicia from alice",
		}, normalize(r.take(t)))

		// Groups, and membership, which is published when it changes
		_, err = published.CreateGroup(ctx, "eng", nil)
		require.NoError(t, err)
		_, err = published.AddGroupUsers(ctx, "eng", "alicia")
		require.NoError(t, err)
		_, err = published.AddGroupUsers(ctx, "eng", "alicia")
		require.NoError(t, err)
		_, err = published.UpdateGroup(ctx, "eng", schema.Attrs{"cn": {"engineering"}})
		require.NoError(t, err)
		_, err = published.DeleteGroup(ctx, "engineering")
		require.NoError(t, err)
		_, err = published.DeleteUser(ctx, "alicia")
		require.NoError(t, err)
		assert.Equal(t, []string{
			"group create eng",
			"group update eng",
			"group update engineering from eng",
			"group delete engineering",
			"user delete alicia",
		}, normalize(r.take(t)))

		// Nothing, when they fail
		_, err = published.CreateGroup(ctx, "", nil)
		assert.Error(t, err)
		_, err = published.Delete(ctx, "ou=missing,"+ou)
		assert.Error(t, err)
		assert.Empty(t, r.take(t))

		// The connection going down, and up
		require.NoError(t, published.Disconnect(ctx))
		require.NoError(t, published.Disconnect(ctx))
		require.NoError(t, published.Connect(ctx))
		require.NoError(t, published.Connect(ctx))
		assert.Equal(t, []string{"connection delete " + host, "connection create " + host}, r.take(t))
	})
}

func Test_ChangesConnectionLost(t *testing.T) {
	// A write which is cancelled loses the connection, and Run connects
	// again
	d := test.NewFake(t, false)
	d.Stall = func(op uint8, _ string) bool { return op == ldapv3.ApplicationAddRequest }
	r := new(recorder)
	m, err := manager.New(manager.WithUrl(d.URL("ldap")), manager.WithBaseDN("dc=example,dc=test"), manager.WithBroadcaster(r))
	require.NoError(t, err)
	require.NoError(t, m.Connect(context.Background()))
	host := strings.TrimPrefix(d.URL("ldap"), "ldap://admin:secret@")

	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(runCtx, slogDiscard()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = m.Create(ctx, "ou=a", schema.Attrs{"objectClass": {"organizationalUnit"}, "ou": {"a"}})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Eventually(t, func() bool { return d.Connections() == 2 }, 5*time.Second, 10*time.Millisecond)
	stop()
	require.NoError(t, <-done)

	assert.Equal(t, []string{
		"connection create " + host,
		"connection delete " + host,
		"connection create " + host,
		"connection delete " + host,
	}, r.take(t))
}

// normalize removes the spaces after commas in DNs, which directories add
// as they like
func normalize(lines []string) []string {
	for i, line := range lines {
		lines[i] = strings.ReplaceAll(line, ", ", ",")
	}
	return lines
}
