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

package schema

import (
	"net/url"
	"testing"

	// Packages
	auth "github.com/djthorpe/go-auth"
	ldap "github.com/go-ldap/ldap/v3"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_object_001(t *testing.T) {
	t.Run("ObjectLDIF", func(t *testing.T) {
		assert := assert.New(t)

		object := &Object{
			DN: "uid=jdoe,ou=people,dc=example,dc=com",
			Values: url.Values{
				"mail":        {"jdoe@example.com"},
				"cn":          {"John Doe"},
				"objectClass": {"inetOrgPerson", "top"},
			},
		}

		assert.Equal(
			"dn: uid=jdoe,ou=people,dc=example,dc=com\n"+
				"cn: John Doe\n"+
				"mail: jdoe@example.com\n"+
				"objectClass: inetOrgPerson\n"+
				"objectClass: top\n",
			object.LDIF(),
		)
	})

	t.Run("ObjectLDIFEncodesUnsafeValues", func(t *testing.T) {
		assert := assert.New(t)

		object := &Object{
			DN: "uid=jdoe,ou=people,dc=example,dc=com",
			Values: url.Values{
				"cn": {" John Doe"},
			},
		}

		assert.Equal(
			"dn: uid=jdoe,ou=people,dc=example,dc=com\n"+
				"cn:: IEpvaG4gRG9l\n",
			object.LDIF(),
		)
	})

	t.Run("ObjectLDIFWritesEmptyAttributeValue", func(t *testing.T) {
		assert := assert.New(t)

		object := &Object{
			DN: "uid=jdoe,ou=people,dc=example,dc=com",
			Values: url.Values{
				"description": {},
			},
		}

		assert.Equal(
			"dn: uid=jdoe,ou=people,dc=example,dc=com\n"+
				"description:\n",
			object.LDIF(),
		)
	})

	t.Run("PasswordResponseLDIF", func(t *testing.T) {
		assert := assert.New(t)

		response := PasswordResponse{
			Object: Object{
				DN: "uid=jdoe,ou=people,dc=example,dc=com",
				Values: url.Values{
					"cn": {"John Doe"},
				},
			},
			GeneratedPassword: "generated-secret",
		}

		assert.Equal(
			"# generated-password: generated-secret\n"+
				"dn: uid=jdoe,ou=people,dc=example,dc=com\n"+
				"cn: John Doe\n",
			response.LDIF(),
		)
	})

	t.Run("PasswordResponseLDIFEncodesUnsafePassword", func(t *testing.T) {
		assert := assert.New(t)

		response := PasswordResponse{
			Object:            Object{DN: "uid=jdoe,ou=people,dc=example,dc=com"},
			GeneratedPassword: " leading-space",
		}

		assert.Equal(
			"# generated-password:: IGxlYWRpbmctc3BhY2U=\n"+
				"dn: uid=jdoe,ou=people,dc=example,dc=com\n",
			response.LDIF(),
		)
	})

	t.Run("ObjectListLDIF", func(t *testing.T) {
		assert := assert.New(t)

		list := &ObjectList{Body: []*Object{
			{
				DN: "uid=jdoe,ou=people,dc=example,dc=com",
				Values: url.Values{
					"cn": {"John Doe"},
				},
			},
			nil,
			{
				DN: "uid=asmith,ou=people,dc=example,dc=com",
				Values: url.Values{
					"cn": {"Alice Smith"},
				},
			},
		}}

		assert.Equal(
			"# objects: 2\n"+
				"version: 1\n\n"+
				"dn: uid=jdoe,ou=people,dc=example,dc=com\n"+
				"cn: John Doe\n\n"+
				"dn: uid=asmith,ou=people,dc=example,dc=com\n"+
				"cn: Alice Smith\n",
			list.LDIF(),
		)
	})

	t.Run("EmptyObjectListLDIF", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("# objects: 0\nversion: 1\n", (&ObjectList{}).LDIF())
	})

	t.Run("ObjectWithPasswordEmbedsGeneratedPassword", func(t *testing.T) {
		assert := assert.New(t)
		password := "generated-secret"

		response := (&Object{
			DN:     "uid=jdoe,ou=people,dc=example,dc=com",
			Values: url.Values{"cn": {"John Doe"}},
		}).WithPassword(&password)

		if assert.NotNil(response) {
			assert.Equal("generated-secret", response.GeneratedPassword)
			assert.Equal("uid=jdoe,ou=people,dc=example,dc=com", response.DN)
			assert.Equal([]string{"John Doe"}, response.Values["cn"])
		}
	})

	t.Run("ObjectWithPasswordIgnoresEmptyPassword", func(t *testing.T) {
		assert := assert.New(t)
		empty := "   "

		response := (&Object{DN: "uid=jdoe,ou=people,dc=example,dc=com", Values: url.Values{}}).WithPassword(&empty)

		if assert.NotNil(response) {
			assert.Empty(response.GeneratedPassword)
			assert.Equal("uid=jdoe,ou=people,dc=example,dc=com", response.DN)
		}
	})

	t.Run("NilObjectWithPasswordReturnsEmptyResponse", func(t *testing.T) {
		assert := assert.New(t)
		password := "generated-secret"

		response := ((*Object)(nil)).WithPassword(&password)

		if assert.NotNil(response) {
			assert.Empty(response.GeneratedPassword)
			assert.Empty(response.DN)
		}
	})

	t.Run("NewObjectInitializesValues", func(t *testing.T) {
		assert := assert.New(t)

		object := NewObject("uid=jdoe", "ou=people", "dc=example", "dc=com")

		if assert.NotNil(object) {
			assert.Equal("uid=jdoe,ou=people,dc=example,dc=com", object.DN)
			assert.NotNil(object.Values)
			assert.Empty(object.Values)
		}
	})

	t.Run("NewObjectFromEntryCopiesAttributes", func(t *testing.T) {
		assert := assert.New(t)

		object := NewObjectFromEntry(&ldap.Entry{
			DN: "uid=jdoe,ou=people,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"John Doe"}},
				{Name: "mail", Values: []string{"jdoe@example.com"}},
			},
		})

		if assert.NotNil(object) {
			assert.Equal("uid=jdoe,ou=people,dc=example,dc=com", object.DN)
			assert.Equal([]string{"John Doe"}, object.Values["cn"])
			assert.Equal([]string{"jdoe@example.com"}, object.Values["mail"])
		}
	})

	t.Run("ObjectGetAndGetAll", func(t *testing.T) {
		assert := assert.New(t)

		object := &Object{Values: url.Values{
			"cn":          {"John Doe", "Johnny"},
			"description": {},
		}}

		if value := object.Get("CN"); assert.NotNil(value) {
			assert.Equal("John Doe", *value)
		}
		if value := object.Get("description"); assert.NotNil(value) {
			assert.Equal("", *value)
		}
		assert.Nil(object.Get("mail"))
		assert.Equal([]string{"John Doe", "Johnny"}, object.GetAll("cn"))
		assert.Equal([]string{"John Doe", "Johnny"}, object.GetAll("CN"))
		assert.Nil(object.GetAll("mail"))
	})

	t.Run("ObjectListRequestQuery", func(t *testing.T) {
		assert := assert.New(t)
		filter := "(objectClass=inetOrgPerson)"
		limit := uint64(25)
		request := ObjectListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 10, Limit: &limit},
			Filter:      &filter,
			Attr:        []string{"cn", "mail"},
		}

		values := request.Query()

		assert.Equal("10", values.Get("offset"))
		assert.Equal("25", values.Get("limit"))
		assert.Equal("(objectClass=inetOrgPerson)", values.Get("filter"))
		assert.Equal([]string{"cn", "mail"}, values["attr"])
	})

	t.Run("StringMethods", func(t *testing.T) {
		assert := assert.New(t)

		assert.NotEmpty((&Object{DN: "uid=jdoe"}).String())
		assert.NotEmpty((&PasswordResponse{}).String())
		assert.NotEmpty((ObjectPutRequest{Attrs: url.Values{"cn": {"John Doe"}}}).String())
		assert.NotEmpty((ObjectPasswordRequest{Old: "old-password"}).String())
		assert.NotEmpty((ObjectList{Count: 1}).String())
		assert.NotEmpty((ObjectListRequest{}).String())
	})

	t.Run("NeedsBase64Encoding", func(t *testing.T) {
		assert := assert.New(t)

		assert.False(needsBase64Encoding("plain-text"))
		assert.False(needsBase64Encoding(""))
		assert.True(needsBase64Encoding(" trailing"))
		assert.True(needsBase64Encoding("trailing "))
		assert.True(needsBase64Encoding(":prefixed"))
		assert.True(needsBase64Encoding("<prefixed"))
		assert.True(needsBase64Encoding("line\nbreak"))
		assert.True(needsBase64Encoding("Jöhn Doe"))
	})

	t.Run("ObjectPutRequestValidateRejectsEmptyAttrs", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), "attrs is required")
	})

	t.Run("ObjectPutRequestValidateRejectsBlankAttributeName", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: url.Values{
			"   ":         {"value"},
			"objectClass": {"inetOrgPerson"},
		}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), "attribute name is required")
	})

	t.Run("ObjectPutRequestValidateRejectsInvalidAttributeOption", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: url.Values{
			"objectClass":             {"inetOrgPerson"},
			"userCertificate;bad opt": {"certificate-data"},
		}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), `invalid attribute name "userCertificate;bad opt"`)
	})

	t.Run("ObjectPutRequestValidateCreate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		attrs, err := (ObjectPutRequest{Attrs: url.Values{
			" objectClass ": {" inetOrgPerson ", " top "},
			" cn ":          {" Test User "},
			" sn":           {" User "},
		}}).ValidateCreate()

		require.NoError(err)
		assert.Equal([]string{"inetOrgPerson", "top"}, attrs["objectClass"])
		assert.Equal([]string{"Test User"}, attrs["cn"])
		assert.Equal([]string{"User"}, attrs["sn"])
	})

	t.Run("ObjectPutRequestValidateCreateRejectsMissingObjectClass", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: url.Values{"cn": {"Test User"}}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), "attrs.objectClass is required")
	})

	t.Run("ObjectPutRequestValidateCreateRejectsDNInBody", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: url.Values{"dn": {"uid=testuser,ou=users,dc=example,dc=com"}, "objectClass": {"inetOrgPerson"}}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), "dn must be provided in the path")
	})

	t.Run("ObjectPutRequestValidateCreateRejectsNullAttribute", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: url.Values{
			"objectClass": nil,
			"cn":          {"Test User"},
		}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), `attribute "objectClass" requires at least one value`)
	})

	t.Run("ObjectPutRequestValidateUpdateAllowsAttributeDelete", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		attrs, err := (ObjectPutRequest{Attrs: url.Values{
			"description": {"   "},
			"mail":        {" user@example.com ", " "},
		}}).ValidateUpdate()

		require.NoError(err)
		assert.Empty(attrs["description"])
		assert.Equal([]string{"user@example.com"}, attrs["mail"])
	})

	t.Run("ObjectPutRequestValidateUpdateAllowsNullAttributeDelete", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		attrs, err := (ObjectPutRequest{Attrs: url.Values{
			"description": nil,
			"mail":        {"user@example.com"},
		}}).ValidateUpdate()

		require.NoError(err)
		assert.Empty(attrs["description"])
		assert.Equal([]string{"user@example.com"}, attrs["mail"])
	})

	t.Run("ObjectPutRequestValidateAllowsLDAPAttributeDescriptions", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		attrs, err := (ObjectPutRequest{Attrs: url.Values{
			"objectClass":            {"inetOrgPerson"},
			"given-name":             {"Test"},
			"2.5.4.3":                {"Test User"},
			"userCertificate;binary": {"certificate-data"},
		}}).ValidateCreate()

		require.NoError(err)
		assert.Equal([]string{"inetOrgPerson"}, attrs["objectClass"])
		assert.Equal([]string{"Test"}, attrs["given-name"])
		assert.Equal([]string{"Test User"}, attrs["2.5.4.3"])
		assert.Equal([]string{"certificate-data"}, attrs["userCertificate;binary"])
	})

	t.Run("ObjectPutRequestValidateRejectsInvalidAttributeDescriptions", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: url.Values{
			"objectClass": {"inetOrgPerson"},
			"cn value":    {"Test User"},
		}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), `invalid attribute name "cn value"`)
	})
}
