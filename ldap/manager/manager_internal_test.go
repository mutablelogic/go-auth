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
	"errors"
	"testing"

	// Packages
	ldapv3 "github.com/go-ldap/ldap/v3"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// The tests of unexported fields and functions, which don't need a
// directory. The others are in manager_test.go.

func Test_New(t *testing.T) {
	t.Run("PlainDefaultsPortAndTakesUserFromURL", func(t *testing.T) {
		m, err := New(WithUrl("ldap://admin:secret@ldap.example.test"), WithBaseDN("dc=example,dc=test"))
		require.NoError(t, err)
		assert.Equal(t, "ldap.example.test", m.Host())
		assert.Equal(t, uint(389), m.Port())
		assert.Equal(t, "cn=admin,dc=example,dc=test", m.User())
		assert.Equal(t, "secret", m.pass)
		assert.Nil(t, m.url.User, "the URL has no credentials")
		assert.Nil(t, m.tls)
	})

	t.Run("SecureDefaultsPortAndOptionsOverrideURL", func(t *testing.T) {
		m, err := New(WithUrl("ldaps://admin:secret@ldap.example.test"), WithBaseDN("dc=example,dc=test"),
			WithUser("cn=manager,dc=example,dc=test"), WithPassword("other"), WithSkipVerify())
		require.NoError(t, err)
		assert.Equal(t, uint(636), m.Port())
		assert.Equal(t, "cn=manager,dc=example,dc=test", m.User(), "a DN is used as it is")
		assert.Equal(t, "other", m.pass)
		require.NotNil(t, m.tls)
		assert.True(t, m.tls.InsecureSkipVerify)
	})

	t.Run("Invalid", func(t *testing.T) {
		for name, opts := range map[string][]Opt{
			"no url":    {WithBaseDN("dc=example,dc=test")},
			"scheme":    {WithUrl("http://admin@ldap.example.test"), WithBaseDN("dc=example,dc=test")},
			"no host":   {WithUrl("ldap://admin@"), WithBaseDN("dc=example,dc=test")},
			"no user":   {WithUrl("ldap://ldap.example.test"), WithBaseDN("dc=example,dc=test")},
			"no dn":     {WithUrl("ldap://admin@ldap.example.test")},
			"bad dn":    {WithUrl("ldap://admin@ldap.example.test"), WithBaseDN("not a dn")},
			"bad users": {WithUrl("ldap://admin@ldap.example.test"), WithBaseDN("dc=example,dc=test"), WithUserDN("")},
		} {
			_, err := New(opts...)
			assert.ErrorIs(t, err, httpresponse.ErrBadRequest, name)
		}
	})

	t.Run("InvalidURLHidesPassword", func(t *testing.T) {
		_, err := New(WithUrl("ldap://admin:secret@ldap.example.test/%zz"), WithBaseDN("dc=example,dc=test"))
		require.ErrorIs(t, err, httpresponse.ErrBadRequest)
		assert.NotContains(t, err.Error(), "secret")
		assert.Contains(t, err.Error(), "%zz", "the cause is kept")
	})
}

func Test_absdn(t *testing.T) {
	m, err := New(WithUrl("ldap://admin@ldap.example.test"), WithBaseDN("dc=example,dc=test"))
	require.NoError(t, err)

	for dn, want := range map[string]string{
		"ou=users":                    "ou=users,dc=example,dc=test",
		"ou=users,dc=example,dc=test": "ou=users,dc=example,dc=test",
		"ou=users,DC=Example,DC=Test": "ou=users,dc=Example,dc=Test",
		"dc=example,dc=test":          "dc=example,dc=test",
	} {
		abs, err := m.absdn(dn)
		require.NoError(t, err, dn)
		assert.Equal(t, want, abs.String(), dn)
	}
	_, err = m.absdn("not a dn")
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
}

func Test_ldaperr(t *testing.T) {
	for code, want := range map[uint16]error{
		ldapv3.LDAPResultInvalidCredentials:     httpresponse.ErrNotAuthorized,
		ldapv3.ErrorFilterCompile:               httpresponse.ErrBadRequest,
		ldapv3.LDAPResultInvalidAttributeSyntax: httpresponse.ErrBadRequest,
		ldapv3.LDAPResultObjectClassViolation:   httpresponse.ErrBadRequest,
		ldapv3.LDAPResultNamingViolation:        httpresponse.ErrBadRequest,
		ldapv3.LDAPResultUnwillingToPerform:     httpresponse.ErrBadRequest,
		ldapv3.LDAPResultNoSuchObject:           httpresponse.ErrNotFound,
		ldapv3.LDAPResultEntryAlreadyExists:     httpresponse.ErrConflict,
		ldapv3.LDAPResultConstraintViolation:    httpresponse.ErrConflict,
		ldapv3.LDAPResultBusy:                   httpresponse.ErrInternalError,
	} {
		err := ldaperr(&ldapv3.Error{ResultCode: code, Err: errors.New("reason")})
		assert.ErrorIs(t, err, want, ldapv3.LDAPResultCodeMap[code])
	}

	// A wrapped LDAP error is translated, and others are kept
	err := ldaperr(errors.Join(errors.New("search failed"), &ldapv3.Error{ResultCode: ldapv3.ErrorFilterCompile, Err: errors.New("ldap: filter does not start with an '('")}))
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	assert.Contains(t, err.Error(), "filter does not start")
	other := errors.New("other")
	assert.Equal(t, other, ldaperr(other))
	assert.NoError(t, ldaperr(nil))

	// A connection which is closed already isn't an error to close
	assert.True(t, isIgnorableLDAPDisconnectError(&ldapv3.Error{ResultCode: ldapv3.ErrorNetwork, Err: errors.New("ldap: connection closed")}))
	assert.True(t, isIgnorableLDAPDisconnectError(errors.New("ldap: connection closed")))
	assert.False(t, isIgnorableLDAPDisconnectError(errors.New("some other error")))
}
