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
	"bytes"
	"log"
	"strings"
	"testing"

	// Packages
	schemadef "github.com/mutablelogic/go-auth/ldap/parser/schema"
	pg "github.com/mutablelogic/go-pg"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	assert "github.com/stretchr/testify/assert"
)

func TestAttributeTypeParseAndHelpers(t *testing.T) {
	t.Run("ParseAttributeType", func(t *testing.T) {
		assert := assert.New(t)

		attributeType, err := ParseAttributeType("( 2.5.4.3 NAME 'cn' DESC 'Common Name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} )")

		if assert.NoError(err) && assert.NotNil(attributeType) {
			assert.Equal("2.5.4.3", attributeType.NumericOID)
			assert.Equal([]string{"cn"}, attributeType.Name)
			assert.Equal("cn", attributeType.Identifier())
			assert.NotEmpty(attributeType.String())
		}
	})

	t.Run("ParseAttributeTypeRejectsInvalidValue", func(t *testing.T) {
		assert := assert.New(t)

		attributeType, err := ParseAttributeType("not valid")

		assert.Error(err)
		assert.Nil(attributeType)
	})

	t.Run("MatchesAdditionalFlags", func(t *testing.T) {
		assert := assert.New(t)
		filter := "2.5.4.3"
		usage := AttributeUsageDirectoryOperation
		superior := "name"
		obsolete := true
		singleValue := true
		collective := true
		noUserModification := true
		attributeType := &AttributeType{&schemadef.AttributeTypeSchema{
			NumericOID:         "2.5.4.3",
			Name:               []string{"cn"},
			SuperType:          "name",
			Usage:              schemadef.AttributeUsageDirectoryOperation,
			Obsolete:           true,
			SingleValue:        true,
			Collective:         true,
			NoUserModification: true,
		}}

		assert.True(attributeType.Matches(AttributeTypeListRequest{
			Filter:             &filter,
			Usage:              &usage,
			Superior:           &superior,
			Obsolete:           &obsolete,
			SingleValue:        &singleValue,
			Collective:         &collective,
			NoUserModification: &noUserModification,
		}))
	})

	t.Run("IdentifierFallsBackToOID", func(t *testing.T) {
		assert := assert.New(t)

		attributeType := &AttributeType{&schemadef.AttributeTypeSchema{NumericOID: "2.5.4.3"}}

		assert.Equal("2.5.4.3", attributeType.Identifier())
		assert.Empty(((*AttributeType)(nil)).Identifier())
	})

	t.Run("MatchesRejectsNilReceiver", func(t *testing.T) {
		assert := assert.New(t)

		assert.False(((*AttributeType)(nil)).Matches(AttributeTypeListRequest{}))
		assert.False((&AttributeType{}).Matches(AttributeTypeListRequest{}))
	})

	t.Run("MatchesRejectsMismatchedFields", func(t *testing.T) {
		assert := assert.New(t)
		usage := AttributeUsageDSAOperation
		superior := "uid"
		obsolete := true
		singleValue := false
		collective := true
		noUserModification := true
		attributeType := &AttributeType{&schemadef.AttributeTypeSchema{
			NumericOID:         "2.5.4.3",
			Name:               []string{"cn"},
			SuperType:          "name",
			Usage:              schemadef.AttributeUsageUserApplications,
			Obsolete:           false,
			SingleValue:        true,
			Collective:         false,
			NoUserModification: false,
		}}

		assert.False(attributeType.Matches(AttributeTypeListRequest{Usage: &usage}))
		assert.False(attributeType.Matches(AttributeTypeListRequest{Superior: &superior}))
		assert.False(attributeType.Matches(AttributeTypeListRequest{Obsolete: &obsolete}))
		assert.False(attributeType.Matches(AttributeTypeListRequest{SingleValue: &singleValue}))
		assert.False(attributeType.Matches(AttributeTypeListRequest{Collective: &collective}))
		assert.False(attributeType.Matches(AttributeTypeListRequest{NoUserModification: &noUserModification}))
	})

	t.Run("StringMethods", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("userApplications", AttributeUsageUserApplications.String())
		assert.True(strings.Contains((AttributeTypeListRequest{}).String(), "{}"))
		assert.True(strings.Contains((AttributeTypeListResponse{}).String(), "0"))
	})
}

func TestAttributeTypeListRequestAndMatching(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		assert := assert.New(t)
		filter := "cn"
		usage := AttributeUsageUserApplications
		superior := "name"
		obsolete := false
		singleValue := true
		collective := false
		noUserModification := false
		limit := uint64(25)
		req := AttributeTypeListRequest{
			OffsetLimit:        pg.OffsetLimit{Offset: 10, Limit: &limit},
			Filter:             &filter,
			Usage:              &usage,
			Superior:           &superior,
			Obsolete:           &obsolete,
			SingleValue:        &singleValue,
			Collective:         &collective,
			NoUserModification: &noUserModification,
		}

		values := req.Query()
		assert.Equal("10", values.Get("offset"))
		assert.Equal("25", values.Get("limit"))
		assert.Equal("cn", values.Get("filter"))
		assert.Equal("userApplications", values.Get("usage"))
		assert.Equal("name", values.Get("superior"))
		assert.Equal("false", values.Get("obsolete"))
		assert.Equal("true", values.Get("singleValue"))
		assert.Equal("false", values.Get("collective"))
		assert.Equal("false", values.Get("noUserModification"))
	})

	t.Run("MatchesFilters", func(t *testing.T) {
		assert := assert.New(t)
		filter := "CN"
		usage := AttributeUsageUserApplications
		superior := "name"
		singleValue := true
		attributeType := &AttributeType{&schemadef.AttributeTypeSchema{
			NumericOID:         "2.5.4.3",
			Name:               []string{"cn"},
			Description:        "Common Name",
			SuperType:          "name",
			SingleValue:        true,
			Collective:         false,
			NoUserModification: false,
			Usage:              schemadef.AttributeUsageUserApplications,
		}}

		assert.True(attributeType.Matches(AttributeTypeListRequest{
			Filter:      &filter,
			Usage:       &usage,
			Superior:    &superior,
			SingleValue: &singleValue,
		}))
	})

	t.Run("RejectsPartialFilterMatch", func(t *testing.T) {
		assert := assert.New(t)
		filter := "c"
		attributeType := &AttributeType{&schemadef.AttributeTypeSchema{
			NumericOID: "2.5.4.3",
			Name:       []string{"cn"},
		}}

		assert.False(attributeType.Matches(AttributeTypeListRequest{Filter: &filter}))
	})

	t.Run("UsageFieldHasEnumSchema", func(t *testing.T) {
		assert := assert.New(t)

		schema := jsonschema.MustFor[AttributeTypeListRequest]()
		prop := schema.Properties["usage"]
		if assert.NotNil(prop) {
			assert.Equal([]any{"userApplications", "directoryOperation", "distributedOperation", "dSAOperation"}, prop.Enum)
		}
	})

	t.Run("ParseAttributeTypeRejectsVendorSpecificOIDQuietly", func(t *testing.T) {
		assert := assert.New(t)
		var output bytes.Buffer
		writer := log.Writer()

		log.SetOutput(&output)
		defer log.SetOutput(writer)

		attributeType, err := ParseAttributeType("( NetscapeLDAPattributeType:198 NAME 'memberURL' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 X-ORIGIN 'Netscape Directory Server' )")

		assert.Error(err)
		assert.Nil(attributeType)
		assert.Empty(strings.TrimSpace(output.String()))
	})
}
