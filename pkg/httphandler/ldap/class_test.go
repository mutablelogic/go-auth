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

	assert "github.com/stretchr/testify/assert"
)

func Test_class_001(t *testing.T) {
	t.Run("ClassHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := ClassHandler(nil)

		assert.Equal("class", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("List object classes", spec.Get.Summary)
			if assert.Len(spec.Get.Parameters, 8) {
				assert.Equal("filter", spec.Get.Parameters[0].Name)
				assert.Nil(spec.Get.Parameters[0].Schema.Enum)
				assert.Equal("kind", spec.Get.Parameters[1].Name)
				assert.Equal([]any{"ABSTRACT", "STRUCTURAL", "AUXILIARY"}, spec.Get.Parameters[1].Schema.Enum)
			}
		}
	})
}

func Test_class_002(t *testing.T) {
	t.Run("AttrHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := AttrHandler(nil)

		assert.Equal("attr", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("List attribute types", spec.Get.Summary)
			if assert.Len(spec.Get.Parameters, 9) {
				assert.Equal("filter", spec.Get.Parameters[0].Name)
				assert.Nil(spec.Get.Parameters[0].Schema.Enum)
				assert.Equal("usage", spec.Get.Parameters[1].Name)
				assert.Equal([]any{"userApplications", "directoryOperation", "distributedOperation", "dSAOperation"}, spec.Get.Parameters[1].Schema.Enum)
				// Verify the enum on 'usage' did not leak onto the 'filter' schema
				assert.Nil(spec.Get.Parameters[0].Schema.Enum)
			}
		}
	})
}
