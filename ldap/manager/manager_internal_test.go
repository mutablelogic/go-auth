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
	"net/url"
	"testing"

	// Packages
	ldapv3 "github.com/go-ldap/ldap/v3"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
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
		ldapv3.LDAPResultInvalidCredentials:       httpresponse.ErrNotAuthorized,
		ldapv3.ErrorFilterCompile:                 httpresponse.ErrBadRequest,
		ldapv3.LDAPResultInvalidAttributeSyntax:   httpresponse.ErrBadRequest,
		ldapv3.LDAPResultObjectClassViolation:     httpresponse.ErrBadRequest,
		ldapv3.LDAPResultNamingViolation:          httpresponse.ErrBadRequest,
		ldapv3.LDAPResultUnwillingToPerform:       httpresponse.ErrBadRequest,
		ldapv3.LDAPResultNoSuchObject:             httpresponse.ErrNotFound,
		ldapv3.LDAPResultInsufficientAccessRights: httpresponse.ErrForbidden,
		ldapv3.LDAPResultEntryAlreadyExists:       httpresponse.ErrConflict,
		ldapv3.LDAPResultConstraintViolation:      httpresponse.ErrConflict,
		ldapv3.LDAPResultNotAllowedOnNonLeaf:      httpresponse.ErrConflict,
		ldapv3.LDAPResultUndefinedAttributeType:   httpresponse.ErrBadRequest,
		ldapv3.LDAPResultNotAllowedOnRDN:          httpresponse.ErrBadRequest,
		ldapv3.LDAPResultInvalidDNSyntax:          httpresponse.ErrBadRequest,
		ldapv3.LDAPResultBusy:                     httpresponse.ErrInternalError,
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

func Test_renameTarget(t *testing.T) {
	dn, err := schema.NewDN("uid=s,ou=users,dc=example,dc=com")
	require.NoError(t, err)

	// A new value of the RDN's attribute renames, under the same parent
	target, rdn, err := renameTarget(dn, url.Values{"UID": {"sam"}})
	require.NoError(t, err)
	assert.Equal(t, "uid=sam", rdn)
	assert.Equal(t, "uid=sam,ou=users,dc=example,dc=com", target)

	// Others don't
	target, rdn, err = renameTarget(dn, url.Values{"cn": {"Sam"}, "uid": {"s"}})
	require.NoError(t, err)
	assert.Empty(t, rdn)
	assert.Equal(t, "uid=s,ou=users,dc=example,dc=com", target)

	// The RDN's attribute can't be deleted
	_, _, err = renameTarget(dn, url.Values{"uid": nil})
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
}

func Test_modifyRequest(t *testing.T) {
	// Values replace, including all of the RDN's attribute's after a
	// rename, and none deletes, in order
	modify := modifyRequest("cn=eng2,ou=groups,dc=example,dc=com", url.Values{
		"cn":          {"eng2", "engineering"},
		"mail":        nil,
		"description": {"Engineering"},
	}, nil)
	require.Len(t, modify.Changes, 3)
	assert.Equal(t, "cn", modify.Changes[0].Modification.Type)
	assert.Equal(t, uint(ldapv3.ReplaceAttribute), modify.Changes[0].Operation)
	assert.Equal(t, []string{"eng2", "engineering"}, modify.Changes[0].Modification.Vals)
	assert.Equal(t, "description", modify.Changes[1].Modification.Type)
	assert.Equal(t, uint(ldapv3.ReplaceAttribute), modify.Changes[1].Operation)
	assert.Equal(t, "mail", modify.Changes[2].Modification.Type)
	assert.Equal(t, uint(ldapv3.DeleteAttribute), modify.Changes[2].Operation)

	// Those to skip, in any case, aren't
	modify = modifyRequest("cn=eng2,ou=groups,dc=example,dc=com", url.Values{"CN": {"eng2"}, "description": {"Engineering"}}, map[string]bool{"cn": true})
	require.Len(t, modify.Changes, 1)
	assert.Equal(t, "description", modify.Changes[0].Modification.Type)
}

func Test_unicodePwd(t *testing.T) {
	// Quoted, in UTF-16LE
	assert.Equal(t, "\"\x00a\x00\xe9\x00\"\x00", unicodePwd("aé"))
}

func Test_randomPassword(t *testing.T) {
	a, err := randomPassword()
	require.NoError(t, err)
	b, err := randomPassword()
	require.NoError(t, err)
	assert.Len(t, a, 24)
	assert.NotEqual(t, a, b)

	// Each has at least three classes of character, for Active Directory
	for range 1000 {
		password, err := randomPassword()
		require.NoError(t, err)
		require.GreaterOrEqual(t, passwordClasses(password), 3, password)
	}
}

func Test_passwordClasses(t *testing.T) {
	for password, want := range map[string]int{
		"":           0,
		"abcdef":     1,
		"abcDEF":     2,
		"abcDEF123":  3,
		"abcDEF123_": 4,
		"abc-_":      2,
	} {
		assert.Equal(t, want, passwordClasses(password), password)
	}
}

func Test_parseSchema(t *testing.T) {
	// Definitions which don't parse are left out, and the rest are by name
	classes := parseObjectClasses([]string{
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )",
		"not valid",
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 2.5.6.4 NAME 'Organization' SUP top STRUCTURAL MUST o )",
	})
	require.Len(t, classes, 3)
	assert.Equal(t, []string{"Organization", "person", "top"}, []string{classes[0].Identifier(), classes[1].Identifier(), classes[2].Identifier()})

	attrs := parseAttributeTypes([]string{
		"( 2.5.4.3 NAME 'cn' SUP name )",
		"( 2.5.4.41 NAME 'name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( broken",
	})
	require.Len(t, attrs, 2)
	assert.Equal(t, "cn", attrs[0].Identifier())
	assert.Equal(t, schema.AttributeUsageUserApplications, schema.AttributeUsage(attrs[1].Usage))
}

func Test_listLimit(t *testing.T) {
	assert.Equal(t, uint64(schema.MaxListEntries), listLimit(nil))
	assert.Equal(t, uint64(5), listLimit(types.Ptr(uint64(5))))
	assert.Equal(t, uint64(schema.MaxListEntries), listLimit(types.Ptr(uint64(schema.MaxListEntries+1))))
}

func Test_userNamingAttribute(t *testing.T) {
	assert.Equal(t, "cn", userNamingAttribute([]string{"user", "posixAccount"}), "Active Directory")
	assert.Equal(t, "uid", userNamingAttribute([]string{"inetOrgPerson", "posixAccount"}))
	assert.Equal(t, "uid", userNamingAttribute([]string{"account"}))
	assert.Equal(t, "cn", userNamingAttribute([]string{"person"}))
}

func Test_choose(t *testing.T) {
	subschema := &subschema{classes: parseObjectClasses([]string{
		"( 1.1 NAME 'person' SUP top STRUCTURAL MUST cn )",
		"( 1.2 NAME 'inetOrgPerson' SUP person STRUCTURAL )",
		"( 1.3 NAME 'posixAccount' SUP top AUXILIARY MUST uid )",
		"( 1.4 NAME 'shadowAccount' SUP top AUXILIARY )",
		"( 1.5 NAME 'user' SUP top AUXILIARY )",
	})}

	// The first structural one, which "user" isn't here, and the auxiliary
	// ones, in any case
	assert.Equal(t, []string{"inetOrgPerson", "posixAccount"}, subschema.choose([]string{"user", "inetOrgPerson", "person"}, []string{"posixaccount", "missing"}))
	assert.Nil(t, subschema.choose([]string{"user", "missing"}, []string{"posixAccount"}), "no structural class")
}

func Test_attrSet(t *testing.T) {
	attrs := url.Values{"ObjectClass": {"top"}, "cn": {"a"}}
	attrSet(attrs, "objectClass", []string{"top", "person"})
	assert.Equal(t, url.Values{"objectClass": {"top", "person"}, "cn": {"a"}}, attrs, "in any case")
	attrDelete(attrs, "CN")
	assert.Equal(t, url.Values{"objectClass": {"top", "person"}}, attrs)
}

func Test_memberAttrs(t *testing.T) {
	assert.Equal(t, []string{"member", "memberUid"}, memberAttrs([]string{"top", "groupOfNames", "posixGroup"}))
	assert.Equal(t, []string{"uniqueMember"}, memberAttrs([]string{"groupOfUniqueNames"}))
	assert.Equal(t, []string{"member", "memberUid"}, memberAttrs([]string{"group", "posixGroup"}), "Active Directory")
	assert.Equal(t, []string{"memberUid"}, memberAttrs([]string{"top", "posixGroup"}), "RFC 2307")
	assert.Equal(t, []string{"member"}, memberAttrs([]string{"top"}))
}

func Test_memberValues(t *testing.T) {
	alice := &schema.Object{DN: "uid=alice,ou=users,dc=example,dc=test", Values: schema.Attrs{"uid": {"alice"}, "cn": {"Alice"}}}
	bob := &schema.Object{DN: "cn=bob,ou=users,dc=example,dc=test", Values: schema.Attrs{"cn": {"bob"}}}
	assert.Equal(t, []string{"alice", "bob"}, memberValues("memberUid", []*schema.Object{alice, bob, alice}), "uid, or cn, once")
	assert.Equal(t, []string{alice.DN, bob.DN}, memberValues("member", []*schema.Object{alice, bob}))

	// uids are exact, and DNs equal in any case
	upper := &schema.Object{DN: "UID=Alice,OU=Users,DC=Example,DC=Test", Values: schema.Attrs{"uid": {"Alice"}}}
	assert.Equal(t, []string{"alice", "Alice"}, memberValues("memberUid", []*schema.Object{alice, upper}))
	assert.Equal(t, []string{alice.DN}, memberValues("member", []*schema.Object{alice, upper}))
}

func Test_requiredMember(t *testing.T) {
	assert.Equal(t, "uniqueMember", requiredMember([]string{"top", "groupOfUniqueNames"}))
	assert.Equal(t, "member", requiredMember([]string{"top", "groupOfNames", "posixGroup"}))
	assert.Empty(t, requiredMember([]string{"top", "group"}), "Active Directory")
	assert.Empty(t, requiredMember([]string{"top", "posixGroup"}))
}

func Test_findMember(t *testing.T) {
	current := []string{"UID=Alice, OU=Users,DC=Example,DC=Test", "cn=bob"}
	assert.Equal(t, current[0], findMember("member", current, "uid=alice,ou=users,dc=example,dc=test"), "as the directory has it")
	assert.Empty(t, findMember("member", current, "uid=carol,ou=users,dc=example,dc=test"))
	assert.Equal(t, "alice", findMember("memberUid", []string{"alice"}, "alice"))
	assert.Empty(t, findMember("memberUid", []string{"Alice"}, "alice"), "uids are exact")
}

func Test_memberFilters(t *testing.T) {
	dn, err := ldapv3.ParseDN("uid=a\\2ab,ou=users,dc=example,dc=test")
	require.NoError(t, err)
	assert.Equal(t, `(uid=a\2ab)`, rdnFilter(dn.RDNs[0]), "escaped")
	dn, err = ldapv3.ParseDN("cn=a+sn=b,ou=users,dc=example,dc=test")
	require.NoError(t, err)
	assert.Equal(t, "(&(cn=a)(sn=b))", rdnFilter(dn.RDNs[0]))

	assert.Equal(t, "(uid=a)", andFilter(nil, "(uid=a)"))
	assert.Equal(t, "(uid=a)", andFilter(types.Ptr(""), "(uid=a)"))
	assert.Equal(t, "(&(sn=b)(uid=a))", andFilter(types.Ptr("(sn=b)"), "(uid=a)"))
}

func Test_sameRow(t *testing.T) {
	assert.True(t, sameRow(schema.TableObject, "OU=a, DC=Example,DC=org", "ou=a,dc=example,dc=org"))
	assert.False(t, sameRow(schema.TableObject, "ou=b,dc=example,dc=org", "ou=a,dc=example,dc=org"))
	assert.True(t, sameRow(schema.TableUser, "Alice", "alice"))
	assert.False(t, sameRow(schema.TableUser, "alicia", "alice"))

	// Names are names, though they look like DNs
	assert.False(t, sameRow(schema.TableGroup, "cn=a,dc=x", "cn=a, dc=x"))
	assert.Equal(t, "alice", rdnValue("UID=alice,ou=users,dc=example,dc=org"))
	assert.Empty(t, rdnValue("not a dn"))
}

func Test_isPassword(t *testing.T) {
	for _, name := range []string{"userPassword", "USERPASSWORD", "userPassword;binary", "2.5.4.35", "2.5.4.35;x", "unicodePwd", "unicodePwd;binary", "1.2.840.113556.1.4.90"} {
		assert.True(t, isPassword(name), name)
	}
	for _, name := range []string{"cn", "2.5.4.3", "userPasswordx", "unicodePwdHistory"} {
		assert.False(t, isPassword(name), name)
	}
	assert.True(t, isUserPassword("2.5.4.35;binary"))
	assert.False(t, isUserPassword("unicodePwd"))
}

func Test_classFilter(t *testing.T) {
	assert.Equal(t, "(objectClass=person)", classFilter([]string{"top", "person"}))
	assert.Equal(t, "(|(objectClass=a)(objectClass=b\\2a))", classFilter([]string{"a", "b*"}))
	assert.Equal(t, "(!(objectClass=*))", classFilter([]string{"top"}), "none, which nothing matches")
	assert.Equal(t, "(!(objectClass=*))", classFilter(nil))
}

func Test_superiors(t *testing.T) {
	subschema := &subschema{classes: parseObjectClasses([]string{
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )",
		"( 2.5.6.7 NAME 'organizationalPerson' SUP 2.5.6.6 STRUCTURAL )",
		"( 1.9 SUP top AUXILIARY )",
		"( 1.10 NAME 'extra' SUP 1.9 AUXILIARY )",
		"( 1.11 NAME 'other' SUP top STRUCTURAL )",
	})}
	require.Len(t, subschema.classes, 6)

	// By name or OID, and a superior without a name by its OID
	assert.Equal(t, map[string]bool{"organizationalperson": true, "person": true, "top": true}, subschema.superiors([]string{"organizationalPerson"}), "a superior by OID")
	assert.Equal(t, map[string]bool{"extra": true, "1.9": true, "top": true}, subschema.superiors([]string{"EXTRA"}), "a superior without a name")
	assert.Equal(t, map[string]bool{"person": true, "top": true}, subschema.superiors([]string{"2.5.6.6", "missing"}))
}
