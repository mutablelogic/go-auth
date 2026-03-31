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

package certmanager

import (
	"net/http"
	"testing"

	// Packages
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

type registeredRoute struct {
	path     string
	params   *jsonschema.Schema
	pathitem httprequest.PathItem
}

type fakeRouter struct {
	routes []registeredRoute
	err    error
}

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {}
func (f *fakeRouter) Spec() *openapi.Spec                              { return new(openapi.Spec) }
func (f *fakeRouter) RegisterPath(path string, params *jsonschema.Schema, pathitem httprequest.PathItem) error {
	f.routes = append(f.routes, registeredRoute{path: path, params: params, pathitem: pathitem})
	return f.err
}

func TestRegisterCertManagerHandlers(t *testing.T) {
	t.Run("RegistersExpectedRoutes", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		router := new(fakeRouter)

		err := RegisterCertManagerHandlers(nil, router, false)
		require.NoError(err)
		require.Len(router.routes, 8)

		paths := make([]string, 0, len(router.routes))
		for _, route := range router.routes {
			paths = append(paths, route.path)
		}
		assert.Contains(paths, "ca")
		assert.Contains(paths, "ca/{name}/renew")
		assert.Contains(paths, "ca/{name}/{serial}/renew")
		assert.Contains(paths, "cert")
		assert.Contains(paths, "cert/{name}")
		assert.Contains(paths, "cert/{name}/{serial}")
		assert.Contains(paths, "cert/{name}/renew")
		assert.Contains(paths, "cert/{name}/{serial}/renew")
		for _, route := range router.routes {
			assert.NotNil(route.pathitem)
		}
	})
}
