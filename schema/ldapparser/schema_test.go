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
	"testing"

	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestObjectClassSchemaJSONSchema(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	schema := jsonschema.MustFor[ObjectClassSchema]()

	numericOID := schema.Properties["numericOid"]
	require.NotNil(numericOID)
	assert.Equal("Numeric object identifier for the object class definition", numericOID.Description)

	classKind := schema.Properties["classKind"]
	require.NotNil(classKind)
	assert.Equal("Object class kind", classKind.Description)
	assert.Equal([]any{"ABSTRACT", "STRUCTURAL", "AUXILIARY"}, classKind.Enum)

	extensions := schema.Properties["extensions"]
	require.NotNil(extensions)
	assert.Equal("Vendor-specific extension values keyed by extension name", extensions.Description)
}

func TestAttributeTypeSchemaJSONSchema(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	schema := jsonschema.MustFor[AttributeTypeSchema]()

	numericOID := schema.Properties["numericOid"]
	require.NotNil(numericOID)
	assert.Equal("Numeric object identifier for the attribute type definition", numericOID.Description)

	usage := schema.Properties["usage"]
	require.NotNil(usage)
	assert.Equal("Operational usage classification for the attribute type", usage.Description)
	assert.Equal([]any{"userApplications", "directoryOperation", "distributedOperation", "dSAOperation"}, usage.Enum)

	noUserModification := schema.Properties["noUserModification"]
	require.NotNil(noUserModification)
	assert.Equal("Whether user modification is prohibited for the attribute type", noUserModification.Description)
}
