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
	"testing"

	pg "github.com/mutablelogic/go-pg"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	assert "github.com/stretchr/testify/assert"
	parser "github.com/yinyin/go-ldap-schema-parser"
)

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
		attributeType := &AttributeType{&parser.AttributeTypeSchema{
			NumericOID:         "2.5.4.3",
			Name:               []string{"cn"},
			Description:        "Common Name",
			SuperType:          "name",
			SingleValue:        true,
			Collective:         false,
			NoUserModification: false,
			Usage:              parser.AttributeUsageUserApplications,
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
		attributeType := &AttributeType{&parser.AttributeTypeSchema{
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
}
