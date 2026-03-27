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

func Test_object_001(t *testing.T) {
	t.Run("ObjectHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := ObjectHandler(nil)

		assert.Equal("object", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("List objects", spec.Get.Summary)
		}
	})

	t.Run("ObjectResourceHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := ObjectResourceHandler(nil)

		assert.Equal("object/{dn}", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("Get object", spec.Get.Summary)
		}
		if assert.NotNil(spec) && assert.NotNil(spec.Put) {
			assert.Equal("Create object", spec.Put.Summary)
		}
		if assert.NotNil(spec) && assert.NotNil(spec.Patch) {
			assert.Equal("Update object", spec.Patch.Summary)
		}
		if assert.NotNil(spec) && assert.NotNil(spec.Delete) {
			assert.Equal("Delete object", spec.Delete.Summary)
		}
	})

	t.Run("ObjectBindHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := ObjectBindHandler(nil)

		assert.Equal("object/{dn}/bind", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Bind object", spec.Post.Summary)
		}
	})

	t.Run("ObjectPasswordHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := ObjectPasswordHandler(nil)

		assert.Equal("object/{dn}/password", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Change object password", spec.Post.Summary)
		}
	})
}
