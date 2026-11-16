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

package ldap_test

import (
	"context"
	"strings"
	"testing"

	// Packages
	ldap "github.com/mutablelogic/go-auth/auth/provider/ldap"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	ldapschema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	test.Main(m)
}

func Test_Provider(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		// A user, with a password, in a group
		m = test.Manager(t, ctx, server, manager.WithUserDN(test.OU(t, ctx, m)), manager.WithGroupDN(test.OU(t, ctx, m)))
		user, err := m.CreateUser(ctx, "alice", ldapschema.Attrs{
			"cn": {"Alice Smith"}, "sn": {"Smith"}, "mail": {"alice@example.com"},
			"homeDirectory": {"/home/alice"}, "userPassword": {"alice Passw0rd!"},
		}, true)
		require.NoError(t, err)
		_, err = m.CreateGroup(ctx, "staff", nil)
		require.NoError(t, err)
		_, err = m.AddGroupUsers(ctx, "staff", "alice")
		require.NoError(t, err)

		p, err := ldap.New(m, ldap.WithName("directory", "The Directory"))
		require.NoError(t, err)
		assert.Equal(t, schema.ProviderMeta{Name: "directory", Label: "The Directory", Kind: schema.ProviderKindPassword}, p.Meta())

		// The right password is the user's identity, with its groups
		identity, err := p.Exchange(ctx, schema.Credential{Username: "alice", Password: "alice Passw0rd!"})
		require.NoError(t, err)
		assert.Equal(t, "directory", identity.Provider)
		assert.True(t, strings.HasPrefix(identity.Issuer, "ldap://"), identity.Issuer)
		assert.NotEmpty(t, identity.Subject)
		assert.False(t, strings.EqualFold(user.DN, identity.Subject), "an identifier, rather than the DN")
		assert.True(t, strings.EqualFold(user.DN, identity.Claims["dn"].(string)))
		assert.Equal(t, "alice@example.com", identity.Email)
		assert.False(t, identity.EmailVerified)
		assert.Contains(t, []string{"Alice Smith", "alice"}, identity.Name)
		assert.Contains(t, identity.Groups, "staff")

		// The same subject, once it's renamed, which Samba doesn't, and
		// another, when it's deleted, and another is made with the name
		if !server.ActiveDirectory {
			_, err = m.UpdateUser(ctx, "alice", ldapschema.Attrs{"uid": {"alicia"}})
			require.NoError(t, err)
			renamed, err := p.Exchange(ctx, schema.Credential{Username: "alicia", Password: "alice Passw0rd!"})
			require.NoError(t, err)
			assert.Equal(t, identity.Subject, renamed.Subject)
			_, err = m.UpdateUser(ctx, "alicia", ldapschema.Attrs{"uid": {"alice"}})
			require.NoError(t, err)
		}
		_, err = m.DeleteUser(ctx, "alice")
		require.NoError(t, err)
		_, err = m.CreateUser(ctx, "alice", ldapschema.Attrs{
			"cn": {"Alice Jones"}, "sn": {"Jones"}, "homeDirectory": {"/home/alice"}, "userPassword": {"alice Passw0rd!"},
		}, true)
		require.NoError(t, err)
		another, err := p.Exchange(ctx, schema.Credential{Username: "alice", Password: "alice Passw0rd!"})
		require.NoError(t, err)
		assert.NotEqual(t, identity.Subject, another.Subject, "another user, with the same DN")

		// A wrong password, and a user who isn't, are the same error
		_, err = p.Exchange(ctx, schema.Credential{Username: "alice", Password: "wrong"})
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
		_, err = p.Exchange(ctx, schema.Credential{Username: "nobody", Password: "wrong"})
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
		_, err = p.Exchange(ctx, schema.Credential{Username: "alice"})
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	})
}

func Test_ProviderNeedsUsers(t *testing.T) {
	// A manager without users can't be signed in with
	d := test.NewFake(t, false)
	m, err := manager.New(manager.WithUrl(d.URL("ldap")), manager.WithBaseDN("dc=example,dc=test"))
	require.NoError(t, err)
	_, err = ldap.New(m)
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	_, err = ldap.New(nil)
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
}
