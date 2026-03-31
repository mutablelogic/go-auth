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

	"github.com/djthorpe/go-auth/pkg/markdown"
	assert "github.com/stretchr/testify/assert"
)

func Test_object_001(t *testing.T) {
	t.Run("ObjectHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, pathitem := ObjectHandler(nil, &markdown.Document{})

		assert.Equal("object", path)
		spec := pathitem.Spec(path, nil)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("List objects", spec.Get.Summary)
		}
	})

	t.Run("ObjectResourceHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, pathitem := ObjectResourceHandler(nil, &markdown.Document{})

		assert.Equal("object/{dn}", path)
		spec := pathitem.Spec(path, nil)
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

		path, _, pathitem := ObjectBindHandler(nil, &markdown.Document{})

		assert.Equal("object/{dn}/bind", path)
		spec := pathitem.Spec(path, nil)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Bind object", spec.Post.Summary)
		}
	})

	t.Run("ObjectPasswordHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, pathitem := ObjectPasswordHandler(nil, &markdown.Document{})

		assert.Equal("object/{dn}/password", path)
		spec := pathitem.Spec(path, nil)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Change object password", spec.Post.Summary)
		}
	})
}
