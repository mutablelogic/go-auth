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
	"fmt"
	"strings"
	"testing"

	// Packages
	ldap "github.com/mutablelogic/go-auth/auth/provider/ldap"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	ldapschema "github.com/mutablelogic/go-auth/ldap/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// stub is a manager, whose user, alice, has the identifier attributes, and
// is in the groups, which are listed a page at a time
type stub struct {
	ids    ldapschema.Attrs
	groups []string
	userDN string // the DN of the user whose groups were last listed
}

const aliceDN = "uid=alice,ou=users,dc=example,dc=test"

func (s *stub) Status() ldapschema.Status {
	return ldapschema.Status{Host: "ldap.example.test", Port: 389, BaseDN: "dc=example,dc=test", UserDN: "ou=users,dc=example,dc=test", GroupDN: "ou=groups,dc=example,dc=test"}
}

func (s *stub) GetUser(_ context.Context, name string) (*ldapschema.Object, error) {
	return &ldapschema.Object{DN: aliceDN, Values: ldapschema.Attrs{"uid": {name}, "cn": {"Alice"}}}, nil
}

// alice is the stub's user, with an email address
func alice() *ldapschema.Object {
	return &ldapschema.Object{DN: aliceDN, Values: ldapschema.Attrs{"uid": {"alice"}, "cn": {"Alice"}, "mail": {"alice@example.test"}}}
}

func (s *stub) ListUsers(_ context.Context, req ldapschema.UserListRequest) (*ldapschema.ObjectList, error) {
	if req.Filter != nil && strings.Contains(strings.ToLower(*req.Filter), "alice@example.test") {
		return &ldapschema.ObjectList{Count: 1, Body: []*ldapschema.Object{alice()}}, nil
	}
	return &ldapschema.ObjectList{}, nil
}

func (s *stub) Bind(_ context.Context, dn, _ string) (*ldapschema.Object, error) {
	return &ldapschema.Object{DN: dn}, nil
}

func (s *stub) Get(_ context.Context, dn string, attrs ...string) (*ldapschema.Object, error) {
	if len(attrs) == 0 {
		if dn != aliceDN {
			return nil, httpresponse.ErrNotFound.With(dn)
		}
		return alice(), nil
	}
	values := ldapschema.Attrs{}
	for _, attr := range attrs {
		if v, ok := s.ids[attr]; ok {
			values[attr] = v
		}
	}
	return &ldapschema.Object{DN: dn, Values: values}, nil
}

func (s *stub) ListGroups(_ context.Context, req ldapschema.GroupListRequest) (*ldapschema.ObjectList, error) {
	if req.UserDN != nil {
		s.userDN = *req.UserDN
	}
	limit := len(s.groups)
	if req.Limit != nil {
		limit = int(*req.Limit)
	}
	start := min(int(req.Offset), len(s.groups))
	list := &ldapschema.ObjectList{Count: uint64(len(s.groups))}
	for _, cn := range s.groups[start:min(start+limit, len(s.groups))] {
		list.Body = append(list.Body, &ldapschema.Object{DN: "cn=" + cn, Values: ldapschema.Attrs{"cn": {cn}}})
	}
	return list, nil
}

func signIn(t *testing.T, s *stub) *schema.Identity {
	t.Helper()
	p, err := ldap.New(s)
	require.NoError(t, err)
	identity, err := p.Exchange(context.Background(), schema.Credential{Username: "alice", Password: "secret"})
	require.NoError(t, err)
	return identity
}

func Test_Subject(t *testing.T) {
	// The subject is the directory's identifier of the user, which doesn't
	// change, with its DN as a claim, or the DN, when there's none
	guid := string([]byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	for _, tc := range []struct {
		name    string
		ids     ldapschema.Attrs
		subject string
	}{
		{"OpenLDAP", ldapschema.Attrs{"entryUUID": {"6f1b-uuid"}}, "6f1b-uuid"},
		{"389 DS", ldapschema.Attrs{"nsUniqueId": {"a1b2-unique"}}, "a1b2-unique"},
		{"Active Directory", ldapschema.Attrs{"objectGUID": {guid}}, "00112233-4455-6677-8899-aabbccddeeff"},
		{"None", ldapschema.Attrs{}, aliceDN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := signIn(t, &stub{ids: tc.ids})
			assert.Equal(t, tc.subject, identity.Subject)
			assert.Equal(t, aliceDN, identity.Claims["dn"])
			assert.Equal(t, "ldap://ldap.example.test:389/dc=example,dc=test", identity.Issuer)
		})
	}
}

func Test_Groups(t *testing.T) {
	// Every group, a page at a time
	s := &stub{ids: ldapschema.Attrs{"entryUUID": {"u"}}}
	for n := range 1234 {
		s.groups = append(s.groups, fmt.Sprint("group", n))
	}
	identity := signIn(t, s)
	assert.Equal(t, s.groups, identity.Groups)
	assert.Equal(t, "Alice", identity.Name)
}

func Test_Users(t *testing.T) {
	ctx := context.Background()
	s := &stub{ids: ldapschema.Attrs{"entryUUID": {"alice-uuid"}}, groups: []string{"Admins", "staff", "other"}}
	users, err := ldap.NewUsers(s, map[string][]string{"admins": {"ldap:write", "ldap:read"}, "STAFF": {"ldap:read", "cert:read"}})
	require.NoError(t, err)

	t.Run("SignedInWithTheDirectory", func(t *testing.T) {
		identity := signIn(t, s)
		user, err := users.User(ctx, identity)
		require.NoError(t, err)
		assert.Equal(t, &schema.User{ID: "alice-uuid", Name: "Alice", Email: "alice@example.test", Groups: []string{"Admins", "staff", "other"}}, user)
		assert.Equal(t, aliceDN, s.userDN, "the groups of the user's DN, not another's with its name")

		// The scopes of the groups, in any case, once each, in order
		scopes, err := users.Scopes(ctx, user)
		require.NoError(t, err)
		assert.Equal(t, []string{"cert:read", "ldap:read", "ldap:write"}, scopes)

		// Another user, with the DN, isn't the identity's
		s.ids = ldapschema.Attrs{"entryUUID": {"another-uuid"}}
		_, err = users.User(ctx, identity)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
		s.ids = ldapschema.Attrs{"entryUUID": {"alice-uuid"}}
	})

	t.Run("AnotherProvider", func(t *testing.T) {
		// By its verified email address
		user, err := users.User(ctx, &schema.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "g1", Email: "ALICE@example.test", EmailVerified: true})
		require.NoError(t, err)
		assert.Equal(t, "alice-uuid", user.ID)

		// Not when it isn't verified, or isn't a user's
		_, err = users.User(ctx, &schema.Identity{Provider: "google", Subject: "g1", Email: "alice@example.test"})
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
		_, err = users.User(ctx, &schema.Identity{Provider: "google", Subject: "g2", Email: "bob@example.test", EmailVerified: true})
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
	})

	t.Run("Needs", func(t *testing.T) {
		_, err := ldap.NewUsers(nil, nil)
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	})
}

func Test_ParseGroupScopes(t *testing.T) {
	scopes, err := ldap.ParseGroupScopes("admins=ldap:read, ldap:write", "staff=cert:read", " admins =cert:write")
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{"admins": {"ldap:read", "ldap:write", "cert:write"}, "staff": {"cert:read"}}, scopes)
	_, err = ldap.ParseGroupScopes("no-equals")
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	_, err = ldap.ParseGroupScopes("=scope")
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
}
