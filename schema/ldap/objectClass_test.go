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

func TestObjectClassListRequestAndMatching(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		assert := assert.New(t)
		filter := "inetOrgPerson"
		kind := ObjectClassKindStructural
		obsolete := false
		limit := uint64(25)
		req := ObjectClassListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 10, Limit: &limit},
			Filter:      &filter,
			Kind:        &kind,
			Superior:    []string{"top"},
			Must:        []string{"sn"},
			May:         []string{"telephoneNumber"},
			Obsolete:    &obsolete,
		}

		values := req.Query()
		assert.Equal("10", values.Get("offset"))
		assert.Equal("25", values.Get("limit"))
		assert.Equal("inetOrgPerson", values.Get("filter"))
		assert.Equal("STRUCTURAL", values.Get("kind"))
		assert.Equal([]string{"top"}, values["superior"])
		assert.Equal([]string{"sn"}, values["must"])
		assert.Equal([]string{"telephoneNumber"}, values["may"])
		assert.Equal("false", values.Get("obsolete"))
	})

	t.Run("MatchesFilterAndAttributes", func(t *testing.T) {
		assert := assert.New(t)
		filter := "inetorgperson"
		kind := ObjectClassKindStructural
		obsolete := false
		objectClass := &ObjectClass{&parser.ObjectClassSchema{
			NumericOID:   "2.16.840.1.113730.3.2.2",
			Name:         []string{"inetOrgPerson"},
			Description:  "Internet organizational person",
			SuperClasses: []string{"organizationalPerson", "top"},
			ClassKind:    parser.ClassKindStructural,
			Must:         []string{"sn", "cn"},
			May:          []string{"telephoneNumber", "mail"},
			Obsolete:     false,
		}}
		req := ObjectClassListRequest{
			Filter:   &filter,
			Kind:     &kind,
			Superior: []string{"top"},
			Must:     []string{"cn"},
			May:      []string{"mail"},
			Obsolete: &obsolete,
		}

		assert.True(objectClass.Matches(req))
	})

	t.Run("MatchesExactNumericOID", func(t *testing.T) {
		assert := assert.New(t)
		filter := "2.16.840.1.113730.3.2.2"
		objectClass := &ObjectClass{&parser.ObjectClassSchema{
			NumericOID: "2.16.840.1.113730.3.2.2",
			Name:       []string{"inetOrgPerson"},
		}}

		assert.True(objectClass.Matches(ObjectClassListRequest{Filter: &filter}))
	})

	t.Run("RejectsPartialFilterMatch", func(t *testing.T) {
		assert := assert.New(t)
		filter := "inet"
		objectClass := &ObjectClass{&parser.ObjectClassSchema{
			NumericOID:   "2.16.840.1.113730.3.2.2",
			Name:         []string{"inetOrgPerson"},
			Description:  "Internet organizational person",
			SuperClasses: []string{"top"},
		}}

		assert.False(objectClass.Matches(ObjectClassListRequest{Filter: &filter}))
	})

	t.Run("RejectsMissingMatch", func(t *testing.T) {
		assert := assert.New(t)
		kind := ObjectClassKindAuxiliary
		objectClass := &ObjectClass{&parser.ObjectClassSchema{
			NumericOID: "2.5.6.6",
			Name:       []string{"person"},
			ClassKind:  parser.ClassKindStructural,
			Must:       []string{"sn", "cn"},
		}}

		assert.False(objectClass.Matches(ObjectClassListRequest{Kind: &kind}))
		assert.False(objectClass.Matches(ObjectClassListRequest{Must: []string{"uid"}}))
	})

	t.Run("KindFieldHasEnumSchema", func(t *testing.T) {
		assert := assert.New(t)

		schema := jsonschema.MustFor[ObjectClassListRequest]()
		prop := schema.Properties["kind"]
		if assert.NotNil(prop) {
			assert.Equal([]any{"ABSTRACT", "STRUCTURAL", "AUXILIARY"}, prop.Enum)
		}
	})
}
