package schema

import (
	"net/url"
	"testing"

	auth "github.com/djthorpe/go-auth"
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
