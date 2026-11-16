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

package ldapparser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	auth "github.com/mutablelogic/go-auth"
	schemadef "github.com/mutablelogic/go-auth/ldap/parser/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestParseObjectClass(t *testing.T) {
	t.Run("OpenLDAPPerson", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		definition := fixtureLine(t, "openldap.schema", "( 2.5.6.6 NAME 'person'")
		result, err := New(definition).ParseObjectClass()

		require.NoError(err)
		require.NotNil(result)
		assert.Equal("2.5.6.6", result.NumericOID)
		assert.Equal([]string{"person"}, result.Name)
		assert.Equal("RFC2256: a person", result.Description)
		assert.Equal([]string{"top"}, result.SuperClasses)
		assert.Equal(schemadef.ObjectClassKindStructural, result.ClassKind)
		assert.Equal([]string{"sn", "cn"}, result.Must)
		assert.Equal([]string{"userPassword", "telephoneNumber", "seeAlso", "description"}, result.May)
		assert.False(result.Obsolete)
	})

	t.Run("DirectoryServerExtensions", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		definition := fixtureLine(t, "389ds.schema", "( 2.5.6.0 NAME 'top'")
		result, err := New(definition).ParseObjectClass()

		require.NoError(err)
		require.NotNil(result)
		assert.Equal("2.5.6.0", result.NumericOID)
		assert.Equal([]string{"top"}, result.Name)
		assert.Equal(schemadef.ObjectClassKindAbstract, result.ClassKind)
		assert.Equal([]string{"objectClass"}, result.Must)
		assert.Equal(map[string][]string{"X-ORIGIN": {"RFC 4512"}}, result.Extensions)
	})
}

func TestParseObjectClassLists(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Lists are separated by $, and an extension can have more than one value
	result, err := New("( 1.2.3.5 NAME 'example' SUP ( top $ person ) AUXILIARY MUST ( cn $ sn ) MAY mail X-ORIGIN ( 'a' 'b' ) )").ParseObjectClass()
	require.NoError(err)
	assert.Equal([]string{"top", "person"}, result.SuperClasses)
	assert.Equal(schemadef.ObjectClassKindAuxiliary, result.ClassKind)
	assert.Equal([]string{"cn", "sn"}, result.Must)
	assert.Equal([]string{"mail"}, result.May)
	assert.Equal(map[string][]string{"X-ORIGIN": {"a", "b"}}, result.Extensions)
}

func TestParseEscapesAndDescriptorOIDs(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// RFC 4512's escapes, in any case, in descriptions and extensions
	class, err := New(`( 1.2.3.6 NAME 'example' DESC 'Owner\27s \5Centry\5c' X-ORIGIN 'it\27s' )`).ParseObjectClass()
	require.NoError(err)
	assert.Equal(`Owner's \entry\`, class.Description)
	assert.Equal(map[string][]string{"X-ORIGIN": {"it's"}}, class.Extensions)

	// 389 DS's schema has descriptors as OIDs, such as nsCertConfig-oid
	class, err = New("( nsCertConfig-oid NAME 'nsCertConfig' SUP top STRUCTURAL MUST cn )").ParseObjectClass()
	require.NoError(err)
	assert.Equal("nsCertConfig-oid", class.NumericOID)
	attr, err := New("( nsCertConfig-oid NAME 'nsCert' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )").ParseAttributeType()
	require.NoError(err)
	assert.Equal("nsCertConfig-oid", attr.NumericOID)
	assert.Equal("1.3.6.1.4.1.1466.115.121.1.15{256}", attr.Syntax)
}

func TestParseInvalid(t *testing.T) {
	for _, definition := range []string{
		"1.2.3 NAME 'missing paren' )",
		"( 1.2.3 NAME 'unterminated'",
		"( 1.2.3 NAME 'trailing' ) extra",
		"( 1.2.3 NAME ( 'a' 1 ) )",
		"( 1.2. NAME 'bad oid' )",
		"( 1.2.3 NAME 'unterminated )",
		"( 1.2.3 NAME 'a' ; )",
		"( 1.2.3 NAME 'a' DESC )",
		"( 1.2.3{64} NAME 'length' )",
		"( '1.2.3' NAME 'quoted' )",
		"( 1.2.3 NAME 'a' ) 'unterminated",
		"( 1.2.3 NAME 'a' DESC 'bad \\n escape' )",
		"( 1.2.3 NAME 'a' DESC 'short \\2' )",
		"( 1.2.3 NAME 'a' SUP ( ) )",
		"( 1.2.3 NAME 'a' SUP ( $ ) )",
		"( 1.2.3 NAME 'a' SUP ( top $ ) )",
		"( 1.2.3 NAME 'a' SUP ( $ top ) )",
		"( 1.2.3 NAME 'a' SUP ( top person ) )",
		"( 1.2.3 NAME 'a' SUP ( top $ $ person ) )",
	} {
		_, err := New(definition).ParseObjectClass()
		assert.ErrorIs(t, err, auth.ErrBadParameter, definition)
		_, err = New(definition).ParseAttributeType()
		assert.ErrorIs(t, err, auth.ErrBadParameter, definition)
	}
}

func TestParseAttributeType(t *testing.T) {
	t.Run("OpenLDAPAttributeWithSkippedClauses", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		definition := fixtureLine(t, "openldap.schema", "( 2.5.4.5 NAME 'serialNumber'")
		result, err := New(definition).ParseAttributeType()

		require.NoError(err)
		require.NotNil(result)
		assert.Equal("2.5.4.5", result.NumericOID)
		assert.Equal([]string{"serialNumber"}, result.Name)
		assert.Equal("RFC2256: serial number of the entity", result.Description)
		assert.Equal("1.3.6.1.4.1.1466.115.121.1.44{64}", result.Syntax)
	})

	t.Run("SMBLDSQuotedSyntax", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		definition := fixtureLine(t, "smblds.schema", "( 1.2.840.113556.1.4.1998 NAME 'msFVE-VolumeGuid'")
		result, err := New(definition).ParseAttributeType()

		require.NoError(err)
		require.NotNil(result)
		assert.Equal("1.2.840.113556.1.4.1998", result.NumericOID)
		assert.Equal([]string{"msFVE-VolumeGuid"}, result.Name)
		assert.Equal("1.3.6.1.4.1.1466.115.121.1.40", result.Syntax)
		assert.True(result.SingleValue)
	})

	t.Run("FlagsUsageAndExtensions", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		definition := "( 1.2.3.4 NAME ( 'exampleAttr' 'exampleAttribute' ) DESC 'Example attribute' SUP name SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION USAGE dSAOperation X-ORIGIN 'unit-test' )"
		result, err := New(definition).ParseAttributeType()

		require.NoError(err)
		require.NotNil(result)
		assert.Equal("1.2.3.4", result.NumericOID)
		assert.Equal([]string{"exampleAttr", "exampleAttribute"}, result.Name)
		assert.Equal("name", result.SuperType)
		assert.Equal(schemadef.AttributeUsageDSAOperation, result.Usage)
		assert.True(result.SingleValue)
		assert.True(result.Collective)
		assert.True(result.NoUserModification)
		assert.Equal(map[string][]string{"X-ORIGIN": {"unit-test"}}, result.Extensions)
	})

	t.Run("RejectsEmptyDefinition", func(t *testing.T) {
		assert := assert.New(t)

		result, err := New(" ").ParseAttributeType()

		assert.Nil(result)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})
}

func fixtureLine(t *testing.T, name, prefix string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}

	t.Fatalf("fixture line with prefix %q not found in %s", prefix, name)
	return ""
}

func TestParseDefaults(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	class, err := New("( 1.2.3 NAME 'example' SUP top MUST cn )").ParseObjectClass()
	require.NoError(err)
	assert.Equal(schemadef.ObjectClassKindStructural, class.ClassKind, "a class is STRUCTURAL without a kind")

	attr, err := New("( 1.2.4 NAME 'example' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )").ParseAttributeType()
	require.NoError(err)
	assert.Equal(schemadef.AttributeUsageUserApplications, attr.Usage, "an attribute type is for user applications without a usage")
}
