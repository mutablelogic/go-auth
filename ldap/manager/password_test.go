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
	"strings"
	"testing"

	// Packages
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// newUser creates a user in the OU, who can bind with the password, which
// the manager sets, and returns its DN
func newUser(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager, ou, name, password string) string {
	t.Helper()
	attrs := schema.Attrs{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"}, "cn": {name}, "sn": {name}, "uid": {name}}
	if server.ActiveDirectory {
		attrs = schema.Attrs{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {name}, "sAMAccountName": {name}}
	}
	user, err := m.Create(ctx, "cn="+name+","+ou, attrs)
	require.NoError(t, err)
	_, err = m.ChangePassword(ctx, user.DN, schema.ObjectPasswordRequest{New: types.Ptr(password)})
	require.NoError(t, err)

	// An Active Directory user is disabled until it has a password
	if server.ActiveDirectory {
		_, err = m.Update(ctx, user.DN, schema.Attrs{"userAccountControl": {"512"}})
		require.NoError(t, err)
	}
	return user.DN
}

func Test_Bind(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)
		dn := newUser(t, ctx, server, m, ou, "alice", "first Passw0rd!")

		bound, err := m.Bind(ctx, dn, "first Passw0rd!")
		require.NoError(t, err)
		assert.Equal(t, dn, bound.DN)

		_, err = m.Bind(ctx, dn, "wrong Passw0rd!")
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
		_, err = m.Bind(ctx, dn, "first Passw0rd! ")
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized, "spaces count")
		_, err = m.Bind(ctx, dn, "")
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized, "no password")
		_, err = m.Bind(ctx, "cn=missing,"+ou, "first Passw0rd!")
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized, "no user")

		// The manager is still bound as its own user
		whoami, err := m.WhoAmI(ctx)
		require.NoError(t, err)
		assert.NotContains(t, whoami, "alice")
	})
}

func Test_ChangePassword(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)
		dn := newUser(t, ctx, server, m, ou, "bob", "first Passw0rd!")

		// With the old password, as the user
		response, err := m.ChangePassword(ctx, dn, schema.ObjectPasswordRequest{Old: "first Passw0rd!", New: types.Ptr("second Passw0rd!")})
		require.NoError(t, err)
		assert.Equal(t, dn, response.DN)
		assert.Empty(t, response.GeneratedPassword)
		_, err = m.Bind(ctx, dn, "second Passw0rd!")
		assert.NoError(t, err)
		if !server.KeepsOldPassword {
			_, err = m.Bind(ctx, dn, "first Passw0rd!")
			assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized, "the old password")
		}

		// A wrong old password isn't authorised
		_, err = m.ChangePassword(ctx, dn, schema.ObjectPasswordRequest{Old: "wrong Passw0rd!", New: types.Ptr("third Passw0rd!")})
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
		_, err = m.Bind(ctx, dn, "second Passw0rd!")
		assert.NoError(t, err, "unchanged")

		// Reset, without the old password, to a generated one
		response, err = m.ChangePassword(ctx, dn, schema.ObjectPasswordRequest{})
		require.NoError(t, err)
		require.NotEmpty(t, response.GeneratedPassword)
		_, err = m.Bind(ctx, dn, response.GeneratedPassword)
		assert.NoError(t, err)

		// Not found
		_, err = m.ChangePassword(ctx, "cn=missing,"+ou, schema.ObjectPasswordRequest{})
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
	})
}

func Test_PasswordTrace(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)).Tracer("test")

	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)
		dn := newUser(t, ctx, server, m, ou, "carol", "first Passw0rd!")
		recorder.Reset()
		_, err := m.ChangePassword(ctx, dn, schema.ObjectPasswordRequest{Old: "first Passw0rd!", New: types.Ptr("second Passw0rd!")})
		require.NoError(t, err)
		_, err = m.Bind(ctx, dn, "second Passw0rd!")
		require.NoError(t, err)

		// The spans never have a password
		names := []string{}
		for _, span := range recorder.Ended() {
			names = append(names, span.Name())
			for _, attr := range span.Attributes() {
				assert.NotContains(t, attr.Value.Emit(), "Passw0rd", span.Name())
			}
		}
		assert.Equal(t, []string{"ldapmanager.ChangePassword", "ldapmanager.Bind"}, names)
	}, manager.WithTracer(tracer))
}

func Test_ChangePasswordNeedsLDAPS(t *testing.T) {
	// An Active Directory password isn't sent over plain ldap
	d := test.NewFake(t, false)
	dn := "cn=alice,ou=users,dc=example,dc=test"
	d.Set(dn, map[string][]string{"objectClass": {"top", "person", "user"}, "cn": {"alice"}})
	m, err := manager.New(manager.WithUrl(d.URL("ldap")), manager.WithBaseDN("dc=example,dc=test"))
	require.NoError(t, err)
	require.NoError(t, m.Connect(context.Background()))
	defer m.Disconnect(context.Background())

	_, err = m.ChangePassword(context.Background(), dn, schema.ObjectPasswordRequest{New: types.Ptr("first Passw0rd!")})
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	assert.Empty(t, d.Requests("modify"))
}

func Test_PasswordsHashed(t *testing.T) {
	// A password in a create or an update is set as a password, which the
	// directory hashes, rather than stored as it's sent, and isn't returned
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		users := usersIn(t, ctx, server, m)
		stored := func(dn string) {
			t.Helper()
			for _, value := range test.Attribute(t, server, dn, "userPassword") {
				assert.True(t, strings.HasPrefix(value, "{"), "hashed, not %q", value)
				assert.NotContains(t, value, "Passw0rd")
			}
		}
		hidden := func(object *schema.Object) {
			t.Helper()
			assert.Nil(t, object.Get("userPassword"))
			assert.Nil(t, object.Get("unicodePwd"))
		}

		// A user
		user, err := users.CreateUser(ctx, "alice", userAttrs("alice", "first Passw0rd!"), true)
		require.NoError(t, err)
		hidden(user)
		stored(user.DN)
		_, err = users.Bind(ctx, user.DN, "first Passw0rd!")
		assert.NoError(t, err)

		// An update, with the password alone, and with other attributes
		user, err = users.UpdateUser(ctx, "alice", schema.Attrs{"userPassword": {"second Passw0rd!"}})
		require.NoError(t, err)
		hidden(user)
		stored(user.DN)
		_, err = users.Bind(ctx, user.DN, "second Passw0rd!")
		assert.NoError(t, err)
		user, err = users.UpdateUser(ctx, "alice", schema.Attrs{"userPassword": {"third Passw0rd!"}, "description": {"Third"}})
		require.NoError(t, err)
		assert.Equal(t, types.Ptr("Third"), user.Get("description"))
		_, err = users.Bind(ctx, user.DN, "third Passw0rd!")
		assert.NoError(t, err)

		// Reads don't return it
		got, err := users.GetUser(ctx, "alice")
		require.NoError(t, err)
		hidden(got)
		list, err := users.List(ctx, schema.ObjectListRequest{ListRequest: schema.ListRequest{Filter: types.Ptr("(objectClass=person)"), Attr: []string{"userPassword", "cn"}}})
		require.NoError(t, err)
		for _, object := range list.Body {
			hidden(object)
		}

		// One value only
		_, err = users.UpdateUser(ctx, "alice", schema.Attrs{"userPassword": {"a Passw0rd!", "b Passw0rd!"}})
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)

		// A generic entry, which isn't Active Directory's
		if !server.ActiveDirectory {
			ou := test.OU(t, ctx, m)
			object, err := m.Create(ctx, "cn=bob,"+ou, schema.Attrs{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"}, "cn": {"bob"}, "sn": {"Example"}, "userPassword": {"bob Passw0rd!"}})
			require.NoError(t, err)
			hidden(object)
			stored(object.DN)
			_, err = m.Bind(ctx, object.DN, "bob Passw0rd!")
			assert.NoError(t, err)
		}
	})
}

func Test_PasswordsNotAdded(t *testing.T) {
	// The password isn't in the add, but set after it
	d := test.NewFake(t, false)
	m := fakeManager(t, d)
	user, err := m.CreateUser(context.Background(), "alice", userAttrs("alice", "first Passw0rd!"), true)
	require.NoError(t, err)
	assert.Nil(t, user.Get("userPassword"))
	assert.Equal(t, []string{"uid=alice,ou=users,dc=example,dc=test"}, d.Requests("password"))
	assert.Equal(t, []string{"{FAKE}first Passw0rd!"}, d.Entry(user.DN)["userPassword"])
}

func Test_PasswordsReview(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)
		hashed := func(t *testing.T, dn string) {
			t.Helper()
			values := test.Attribute(t, server, dn, "userPassword")
			require.NotEmpty(t, values)
			for _, value := range values {
				assert.True(t, strings.HasPrefix(value, "{"), "hashed, not %q", value)
			}
		}

		if server.ActiveDirectory {
			// A unicodePwd with an option is a password, which enables the
			// user
			users := usersIn(t, ctx, server, m)
			user, err := users.CreateUser(ctx, "alice", schema.Attrs{"sn": {"Example"}, "unicodePwd;binary": {"first Passw0rd!"}}, false)
			require.NoError(t, err)
			assert.Equal(t, types.Ptr("512"), user.Get("userAccountControl"), "enabled")
			_, err = users.Bind(ctx, user.DN, "first Passw0rd!")
			assert.NoError(t, err)
			return
		}

		t.Run("OID", func(t *testing.T) {
			// userPassword by its OID is a password
			object, err := m.Create(ctx, "cn=oid,"+ou, schema.Attrs{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"}, "cn": {"oid"}, "sn": {"Example"}, "2.5.4.35": {"oid Passw0rd!"}})
			require.NoError(t, err)
			assert.Nil(t, object.Get("2.5.4.35"))
			assert.Nil(t, object.Get("userPassword"))
			hashed(t, object.DN)
			_, err = m.Bind(ctx, object.DN, "oid Passw0rd!")
			assert.NoError(t, err)
		})

		t.Run("Required", func(t *testing.T) {
			// A class which needs a userPassword is created, with it hashed
			object, err := m.Create(ctx, "uid=app,"+ou, schema.Attrs{"objectClass": {"top", "account", "simpleSecurityObject"}, "uid": {"app"}, "userPassword": {"app Passw0rd!"}})
			require.NoError(t, err)
			hashed(t, object.DN)
			_, err = m.Bind(ctx, object.DN, "app Passw0rd!")
			assert.NoError(t, err)
		})

		t.Run("RenameUndone", func(t *testing.T) {
			// A rename whose password fails, as a device can't have one, is
			// undone
			_, err := m.Create(ctx, "cn=dev,"+ou, schema.Attrs{"objectClass": {"top", "device"}, "cn": {"dev"}})
			require.NoError(t, err)
			_, err = m.Update(ctx, "cn=dev,"+ou, schema.Attrs{"cn": {"dev2"}, "userPassword": {"dev Passw0rd!"}})
			assert.Error(t, err)
			_, err = m.Get(ctx, "cn=dev,"+ou)
			assert.NoError(t, err, "renamed back")
			_, err = m.Get(ctx, "cn=dev2,"+ou)
			assert.ErrorIs(t, err, httpresponse.ErrNotFound)
		})
	})
}
