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
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Packages
	managerpkg "github.com/mutablelogic/go-auth/auth/manager"
	providerpkg "github.com/mutablelogic/go-auth/auth/provider"
	localprovider "github.com/mutablelogic/go-auth/auth/provider/local"
	authtest "github.com/mutablelogic/go-auth/auth/test"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type registeredRoute struct {
	path     string
	params   *jsonschema.Schema
	pathitem httprequest.PathItem
}

type fakeRouter struct {
	spec   *openapi.Spec
	routes []registeredRoute
	err    error
}

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {}
func (f *fakeRouter) Spec() *openapi.Spec                              { return f.spec }
func (f *fakeRouter) RegisterPath(path string, params *jsonschema.Schema, pathitem httprequest.PathItem) error {
	f.routes = append(f.routes, registeredRoute{path: path, params: params, pathitem: pathitem})
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

var conn authtest.Conn

func TestMain(m *testing.M) {
	authtest.Main(m, &conn)
}

///////////////////////////////////////////////////////////////////////////////
// TESTS

func TestRegisterManagerHandlers(t *testing.T) {
	t.Run("RegistersExpectedRoutes", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := newHTTPTestManager(t)
		router := &fakeRouter{spec: openapi.NewSpec("test", "1.0")}

		err := RegisterManagerHandlers(mgr, router)
		require.NoError(err)
		require.Len(router.routes, 8)

		paths := make([]string, 0, len(router.routes))
		for _, route := range router.routes {
			paths = append(paths, route.path)
			assert.NotNil(route.pathitem.Handler())
		}

		assert.Contains(paths, "config")
		assert.Contains(paths, "changes")
		assert.Contains(paths, "group")
		assert.Contains(paths, "group/{group}")
		assert.Contains(paths, "scope")
		assert.Contains(paths, "user")
		assert.Contains(paths, "user/{user}")
		assert.Contains(paths, "user/{user}/group")
	})

	t.Run("LeavesChangesOpenWhenAuthDisabled", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := newHTTPTestManager(t)
		router := &fakeRouter{spec: openapi.NewSpec("test", "1.0")}

		err := RegisterManagerHandlers(mgr, router)
		require.NoError(err)

		route, ok := router.route("changes")
		require.True(ok)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/changes", nil)
		req.Header.Set("Accept", "application/json")

		route.pathitem.Handler()(res, req)

		require.Equal(http.StatusNotAcceptable, res.Code)
		assert.Contains(res.Body.String(), "text/event-stream")
	})

	t.Run("RegistersChangesRouteUnderAPIPrefix", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := newHTTPTestManager(t)
		router, err := httprouter.NewRouter(context.Background(), "/api", "", "Test API", "1.0.0")
		require.NoError(err)
		require.NoError(RegisterManagerHandlers(mgr, router))

		req := httptest.NewRequest(http.MethodGet, "/api/changes", nil)
		req.Header.Set("Accept", "application/json")
		res := httptest.NewRecorder()

		router.ServeHTTP(res, req)

		assert.Equal(http.StatusNotAcceptable, res.Code)
		assert.Contains(res.Body.String(), "text/event-stream")
	})
}

func newHTTPTestManager(t *testing.T) *managerpkg.Manager {
	t.Helper()
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	managerOpts := []managerpkg.Opt{
		managerpkg.WithPrivateKey(key),
		managerpkg.WithProvider(mustLocalProvider(t, "http://localhost:8084/api", key)),
		managerpkg.WithSessionTTL(15 * time.Minute),
	}
	mgr, err := managerpkg.New(context.Background(), c, managerOpts...)
	require.NoError(t, err)
	require.NoError(t, mgr.Exec(context.Background(), "TRUNCATE auth.user CASCADE"))

	return mgr
}

func mustLocalProvider(t *testing.T, issuer string, key *rsa.PrivateKey) providerpkg.Provider {
	t.Helper()
	provider, err := localprovider.New(issuer, key)
	require.NoError(t, err)
	return provider
}
