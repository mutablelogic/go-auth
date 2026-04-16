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

package ldap

import (
	"net/url"
	"testing"

	schema "github.com/mutablelogic/go-auth/ldap/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestClassHelpers(t *testing.T) {
	t.Run("SubschemaDNFromRootRejectsNil", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		dn, err := subschemaDNFromRoot(nil)

		require.Error(err)
		assert.Empty(dn)
		assert.ErrorIs(err, httpresponse.ErrNotFound)
	})

	t.Run("SubschemaDNFromRootRejectsMissingAttribute", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		dn, err := subschemaDNFromRoot(&schema.Object{DN: "", Values: url.Values{}})

		require.Error(err)
		assert.Empty(dn)
		assert.ErrorIs(err, httpresponse.ErrNotFound)
	})

	t.Run("SubschemaDNFromRootReturnsValue", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		dn, err := subschemaDNFromRoot(&schema.Object{Values: url.Values{schema.AttrSubSchemaDN: {"cn=subschema"}}})

		require.NoError(err)
		assert.Equal("cn=subschema", dn)
	})

	t.Run("ParseObjectClassesSkipsInvalidValues", func(t *testing.T) {
		assert := assert.New(t)

		classes := parseObjectClasses([]string{
			"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
			"not valid",
		})

		if assert.Len(classes, 1) && assert.NotNil(classes[0]) && assert.NotNil(classes[0].ObjectClassSchema) {
			assert.Equal("2.5.6.6", classes[0].NumericOID)
		}
	})

	t.Run("ParseAttributeTypesSkipsInvalidValues", func(t *testing.T) {
		assert := assert.New(t)

		types := parseAttributeTypes([]string{
			"( 2.5.4.3 NAME 'cn' DESC 'Common Name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} )",
			"not valid",
		})

		if assert.Len(types, 1) && assert.NotNil(types[0]) && assert.NotNil(types[0].AttributeTypeSchema) {
			assert.Equal("2.5.4.3", types[0].NumericOID)
		}
	})
}
