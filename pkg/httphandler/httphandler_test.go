package httphandler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
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

func (f *fakeRouter) Spec() *openapi.Spec { return nil }

func (f *fakeRouter) RegisterFunc(path string, handler http.HandlerFunc, middleware bool, spec *openapi.PathItem) error {
	f.routes = append(f.routes, registeredRoute{
		path:       path,
		handler:    handler,
		middleware: middleware,
		spec:       spec,
	})
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

func Test_httphandler_001(t *testing.T) {
	t.Run("RegisterHandlers", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		router := new(fakeRouter)

		err := RegisterHandlers(mgr, router, false)
		require.NoError(err)
		require.Len(router.routes, 16)

		paths := make([]string, 0, len(router.routes))
		for _, route := range router.routes {
			paths = append(paths, route.path)
			assert.NotNil(route.handler)
			assert.NotNil(route.spec)
			assert.True(route.middleware)
		}

		assert.Contains(paths, "changes")
		assert.Contains(paths, "group")
		assert.Contains(paths, "group/{group}")
		assert.Contains(paths, "scope")
		assert.Contains(paths, "user")
		assert.Contains(paths, "user/{user}")
		assert.Contains(paths, "user/{user}/group")
		assert.Contains(paths, "/auth/login")
		assert.Contains(paths, "/auth/credentials")
		assert.Contains(paths, "/auth/code")
		assert.Contains(paths, "/auth/config")
		assert.Contains(paths, "/auth/userinfo")
		assert.Contains(paths, "/auth/refresh")
		assert.Contains(paths, "/auth/revoke")
		assert.Contains(paths, ".well-known/openid-configuration")
		assert.Contains(paths, ".well-known/jwks.json")
	})

	t.Run("RegisterHandlersProtectsChangesWhenAuthEnabled", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		router := new(fakeRouter)

		err := RegisterHandlers(mgr, router, true)
		require.NoError(err)

		route, ok := router.route("changes")
		require.True(ok)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/changes", nil)
		req.Header.Set("Accept", "application/json")

		route.handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "missing bearer token")
	})

	t.Run("RegisterHandlersLeavesChangesOpenWhenAuthDisabled", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		router := new(fakeRouter)

		err := RegisterHandlers(mgr, router, false)
		require.NoError(err)

		route, ok := router.route("changes")
		require.True(ok)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/changes", nil)
		req.Header.Set("Accept", "application/json")

		route.handler(res, req)

		require.Equal(http.StatusNotAcceptable, res.Code)
		assert.Contains(res.Body.String(), "text/event-stream")
	})
}
