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
	"encoding/json"
	"testing"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	auth "github.com/mutablelogic/go-auth"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_object_001(t *testing.T) {
	t.Run("ObjectLDIF", func(t *testing.T) {
		assert := assert.New(t)

		object := &Object{
			DN: "uid=jdoe,ou=people,dc=example,dc=com",
			Values: Attrs{
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
			Values: Attrs{
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
			Values: Attrs{
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
				Values: Attrs{
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
				Values: Attrs{
					"cn": {"John Doe"},
				},
			},
			nil,
			{
				DN: "uid=asmith,ou=people,dc=example,dc=com",
				Values: Attrs{
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
			Values: Attrs{"cn": {"John Doe"}},
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

		response := (&Object{DN: "uid=jdoe,ou=people,dc=example,dc=com", Values: Attrs{}}).WithPassword(&empty)

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

		object := &Object{Values: Attrs{
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
			OffsetLimit: OffsetLimit{Offset: 10, Limit: &limit},
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
		assert.NotEmpty((ObjectPutRequest{Attrs: Attrs{"cn": {"John Doe"}}}).String())
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

		_, err := (ObjectPutRequest{Attrs: Attrs{
			"   ":         {"value"},
			"objectClass": {"inetOrgPerson"},
		}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), "attribute name is required")
	})

	t.Run("ObjectPutRequestValidateRejectsInvalidAttributeOption", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: Attrs{
			"objectClass":             {"inetOrgPerson"},
			"userCertificate;bad opt": {"certificate-data"},
		}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), `invalid attribute name "userCertificate;bad opt"`)
	})

	t.Run("ObjectPutRequestValidateCreate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		attrs, err := (ObjectPutRequest{Attrs: Attrs{
			" objectClass ": {"inetOrgPerson", "top"},
			" cn ":          {"Test User"},
			" sn":           {"User"},
			"userPassword":  {" secret "},
		}}).ValidateCreate()

		require.NoError(err)
		assert.Equal([]string{"inetOrgPerson", "top"}, attrs["objectClass"], "names are trimmed")
		assert.Equal([]string{"Test User"}, attrs["cn"])
		assert.Equal([]string{"User"}, attrs["sn"])
		assert.Equal([]string{" secret "}, attrs["userPassword"], "values are kept as they are")
	})

	t.Run("ObjectPutRequestValidateCreateRejectsMissingObjectClass", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: Attrs{"cn": {"Test User"}}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), "attrs.objectClass is required")
	})

	t.Run("ObjectPutRequestValidateCreateRejectsDNInBody", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: Attrs{"dn": {"uid=testuser,ou=users,dc=example,dc=com"}, "objectClass": {"inetOrgPerson"}}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), "dn must be provided in the path")
	})

	t.Run("ObjectPutRequestValidateCreateRejectsNullAttribute", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (ObjectPutRequest{Attrs: Attrs{
			"objectClass": nil,
			"cn":          {"Test User"},
		}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), `attribute "objectClass" requires at least one value`)
	})

	t.Run("ObjectPutRequestValidateUpdateAllowsAttributeDelete", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		attrs, err := (ObjectPutRequest{Attrs: Attrs{
			"description": {""},
			"mail":        {"user@example.com", ""},
			"title":       {"   "},
		}}).ValidateUpdate()

		require.NoError(err)
		assert.Empty(attrs["description"], "an empty value deletes")
		assert.Equal([]string{"user@example.com"}, attrs["mail"])
		assert.Equal([]string{"   "}, attrs["title"], "spaces are a value")
	})

	t.Run("ObjectPutRequestValidateUpdateAllowsNullAttributeDelete", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		attrs, err := (ObjectPutRequest{Attrs: Attrs{
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

		attrs, err := (ObjectPutRequest{Attrs: Attrs{
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

		_, err := (ObjectPutRequest{Attrs: Attrs{
			"objectClass": {"inetOrgPerson"},
			"cn value":    {"Test User"},
		}}).ValidateCreate()

		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.Contains(err.Error(), `invalid attribute name "cn value"`)
	})
}

func Test_ObjectAttrsCase(t *testing.T) {
	assert := assert.New(t)

	// Attribute names aren't case-sensitive
	attrs, err := ObjectPutRequest{Attrs: Attrs{"OBJECTCLASS": {"top"}, "cn": {"x"}}}.ValidateCreate()
	assert.NoError(err)
	assert.Equal([]string{"top"}, attrs["OBJECTCLASS"])

	_, err = ObjectPutRequest{Attrs: Attrs{"cn": {"x"}, "CN": {"y"}, "objectClass": {"top"}}}.ValidateCreate()
	assert.ErrorIs(err, auth.ErrBadParameter)
	_, err = ObjectPutRequest{Attrs: Attrs{"cn": {"x"}}}.ValidateCreate()
	assert.ErrorIs(err, auth.ErrBadParameter)

	// A nil object has no attributes
	var object *Object
	assert.Nil(object.Get("cn"))
	assert.Nil(object.GetAll("cn"))
}

func Test_AttrsJSON(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	binary := string([]byte{0x30, 0x82, 0xff, 0x00, 0x20})
	object := Object{DN: "cn=test,dc=example,dc=test", Values: Attrs{
		"cn":                     {"Test"},
		"userCertificate;binary": {binary},
	}}
	data, err := json.Marshal(object)
	require.NoError(err)
	assert.JSONEq(`{"dn":"cn=test,dc=example,dc=test","attrs":{"cn":["Test"],"userCertificate;binary":[{"base64":"MIL/ACA="}]}}`, string(data))

	// It reads back, and a request takes the same values
	var decoded Object
	require.NoError(json.Unmarshal(data, &decoded))
	assert.Equal(object, decoded)

	var req ObjectPutRequest
	require.NoError(json.Unmarshal([]byte(`{"attrs":{"jpegPhoto":[{"base64":"/9j/"}],"cn":["a"]}}`), &req))
	assert.Equal([]string{"\xff\xd8\xff"}, req.Attrs["jpegPhoto"])
	assert.Error(json.Unmarshal([]byte(`{"attrs":{"cn":[{"base64":"!"}]}}`), &req))
	assert.Error(json.Unmarshal([]byte(`{"attrs":{"cn":[1]}}`), &req))

	// A password response keeps its own fields
	data, err = json.Marshal(object.WithPassword(types.Ptr("generated")))
	require.NoError(err)
	assert.Contains(string(data), `"generated-password":"generated"`)
}

func Test_MemberListRequests(t *testing.T) {
	assert := assert.New(t)
	users := UserListRequest{ObjectListRequest: ObjectListRequest{Filter: types.Ptr("(sn=a)")}, Group: types.Ptr("eng")}
	assert.Equal("filter=%28sn%3Da%29&group=eng", users.Query().Encode())
	assert.Equal("", UserListRequest{}.Query().Encode())
	assert.NotEmpty(users.String())

	groups := GroupListRequest{User: types.Ptr("alice")}
	assert.Equal("user=alice", groups.Query().Encode())
	assert.NotEmpty(groups.String())
}
