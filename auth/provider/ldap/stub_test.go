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
	"testing"

	// Packages
	ldap "github.com/mutablelogic/go-auth/auth/provider/ldap"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	ldapschema "github.com/mutablelogic/go-auth/ldap/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// stub is a manager, whose user, alice, has the identifier attributes, and
// is in the groups, which are listed a page at a time
type stub struct {
	ids    ldapschema.Attrs
	groups []string
}

const aliceDN = "uid=alice,ou=users,dc=example,dc=test"

func (s *stub) Status() ldapschema.Status {
	return ldapschema.Status{Host: "ldap.example.test", Port: 389, BaseDN: "dc=example,dc=test", UserDN: "ou=users,dc=example,dc=test", GroupDN: "ou=groups,dc=example,dc=test"}
}

func (s *stub) GetUser(_ context.Context, name string) (*ldapschema.Object, error) {
	return &ldapschema.Object{DN: aliceDN, Values: ldapschema.Attrs{"uid": {name}, "cn": {"Alice"}}}, nil
}

func (s *stub) Bind(_ context.Context, dn, _ string) (*ldapschema.Object, error) {
	return &ldapschema.Object{DN: dn}, nil
}

func (s *stub) Get(_ context.Context, dn string, attrs ...string) (*ldapschema.Object, error) {
	values := ldapschema.Attrs{}
	for _, attr := range attrs {
		if v, ok := s.ids[attr]; ok {
			values[attr] = v
		}
	}
	return &ldapschema.Object{DN: dn, Values: values}, nil
}

func (s *stub) ListGroups(_ context.Context, req ldapschema.GroupListRequest) (*ldapschema.ObjectList, error) {
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
