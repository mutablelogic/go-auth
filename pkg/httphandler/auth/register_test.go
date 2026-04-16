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

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
	oidc "github.com/mutablelogic/go-auth/pkg/oidc"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

type registeredRoute struct {
	path       string
	handler    http.HandlerFunc
	middleware bool
	spec       *openapi.PathItem
}

type fakeRouter struct {
	routes []registeredRoute
	err    error
}

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {}
func (f *fakeRouter) Spec() *openapi.Spec                              { return nil }
func (f *fakeRouter) RegisterFunc(path string, handler http.HandlerFunc, middleware bool, spec *openapi.PathItem) error {
	f.routes = append(f.routes, registeredRoute{path: path, handler: handler, middleware: middleware, spec: spec})
	return f.err
}

func (f *fakeRouter) route(path string) (registeredRoute, bool) {
	for _, route := range f.routes {
		if route.path == path {
			return route, true
		}
	}
	return registeredRoute{}, false
}

func TestRegisterAuthHandlers(t *testing.T) {
	t.Run("RegistersExpectedRoutes", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		router := new(fakeRouter)

		err := RegisterAuthHandlers(mgr, router)
		require.NoError(err)
		require.Len(router.routes, 8)

		paths := make([]string, 0, len(router.routes))
		for _, route := range router.routes {
			paths = append(paths, route.path)
			assert.NotNil(route.handler)
			assert.NotNil(route.spec)
			assert.True(route.middleware)
		}

		assert.Contains(paths, oidc.AuthorizationPath)
		assert.Contains(paths, "auth/code")
		assert.Contains(paths, "auth/userinfo")
		assert.Contains(paths, "auth/revoke")
		assert.Contains(paths, oidc.ConfigPath)
		assert.Contains(paths, oidc.ProtectedResourcePath)
		assert.Contains(paths, oidc.JWKSPath)
		assert.Contains(paths, "auth/provider/local")
	})

	t.Run("ProtectsUserInfoAlways", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		router := new(fakeRouter)

		err := RegisterAuthHandlers(mgr, router)
		require.NoError(err)

		route, ok := router.route("auth/userinfo")
		require.True(ok)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)

		route.handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "missing bearer token")
	})
}
