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
