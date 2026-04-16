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
	"testing"

	"github.com/mutablelogic/go-auth/pkg/markdown"
	assert "github.com/stretchr/testify/assert"
)

func Test_class_001(t *testing.T) {
	t.Run("ClassHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, pathitem := ClassHandler(nil, &markdown.Document{})

		assert.Equal("class", path)
		spec := pathitem.Spec(path, nil)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("List object classes", spec.Get.Summary)
			if assert.Len(spec.Get.Parameters, 8) {
				assert.Equal("filter", spec.Get.Parameters[0].Name)
				assert.Nil(spec.Get.Parameters[0].Schema.Enum)
				assert.Equal("kind", spec.Get.Parameters[1].Name)
				assert.Equal([]any{"ABSTRACT", "STRUCTURAL", "AUXILIARY"}, spec.Get.Parameters[1].Schema.Enum)
			}
			response := spec.Get.Responses["200"].Content["application/json"].Schema
			if assert.NotNil(response) {
				assert.Equal("Total number of matching object classes before pagination", response.Properties["count"].Description)
				assert.Equal("Object classes returned for the current page", response.Properties["body"].Description)
				if assert.NotNil(response.Properties["body"]) && assert.NotNil(response.Properties["body"].Items) {
					assert.Equal("Numeric object identifier for the object class definition", response.Properties["body"].Items.Properties["numericOid"].Description)
					assert.Equal([]any{"ABSTRACT", "STRUCTURAL", "AUXILIARY"}, response.Properties["body"].Items.Properties["classKind"].Enum)
				}
			}
		}
	})
}

func Test_class_002(t *testing.T) {
	t.Run("AttrHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, pathitem := AttrHandler(nil, &markdown.Document{})

		assert.Equal("attr", path)
		spec := pathitem.Spec(path, nil)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("List attribute types", spec.Get.Summary)
			if assert.Len(spec.Get.Parameters, 9) {
				assert.Equal("filter", spec.Get.Parameters[1].Name)
				assert.Nil(spec.Get.Parameters[1].Schema.Enum)
				assert.Equal("usage", spec.Get.Parameters[8].Name)
				assert.Equal([]any{"userApplications", "directoryOperation", "distributedOperation", "dSAOperation"}, spec.Get.Parameters[8].Schema.Enum)
				// Verify the enum on 'usage' did not leak onto the 'filter' schema
				assert.Nil(spec.Get.Parameters[1].Schema.Enum)
			}
			response := spec.Get.Responses["200"].Content["application/json"].Schema
			if assert.NotNil(response) {
				assert.Equal("Total number of matching attribute types before pagination", response.Properties["count"].Description)
				assert.Equal("Attribute types returned for the current page", response.Properties["body"].Description)
				if assert.NotNil(response.Properties["body"]) && assert.NotNil(response.Properties["body"].Items) {
					assert.Equal("Numeric object identifier for the attribute type definition", response.Properties["body"].Items.Properties["numericOid"].Description)
					assert.Equal([]any{"userApplications", "directoryOperation", "distributedOperation", "dSAOperation"}, response.Properties["body"].Items.Properties["usage"].Enum)
				}
			}
		}
	})
}
