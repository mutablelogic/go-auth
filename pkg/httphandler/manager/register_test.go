package manager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	managerpkg "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	test "github.com/mutablelogic/go-pg/pkg/test"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

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

var conn test.Conn

func TestMain(m *testing.M) {
	test.Main(m, &conn)
}

///////////////////////////////////////////////////////////////////////////////
// TESTS

func TestRegisterManagerHandlers(t *testing.T) {
	t.Run("RegistersExpectedRoutes", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := newHTTPTestManager(t)
		router := new(fakeRouter)

		err := RegisterManagerHandlers(mgr, router, false)
		require.NoError(err)
		require.Len(router.routes, 7)

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
	})

	t.Run("ProtectsChangesWhenAuthEnabled", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := newHTTPTestManager(t)
		router := new(fakeRouter)

		err := RegisterManagerHandlers(mgr, router, true)
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

	t.Run("LeavesChangesOpenWhenAuthDisabled", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := newHTTPTestManager(t)
		router := new(fakeRouter)

		err := RegisterManagerHandlers(mgr, router, false)
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

	t.Run("RegistersChangesRouteUnderAPIPrefix", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := newHTTPTestManager(t)
		router, err := httprouter.NewRouter(context.Background(), "/api", "", "Test API", "1.0.0")
		require.NoError(err)
		require.NoError(RegisterManagerHandlers(mgr, router, false))

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
		managerpkg.WithOAuthClient(oidc.OAuthClientKeyLocal, "http://localhost:8084/api", "", ""),
		managerpkg.WithSessionTTL(15 * time.Minute),
	}
	mgr, err := managerpkg.New(context.Background(), c, managerOpts...)
	require.NoError(t, err)
	require.NoError(t, mgr.Exec(context.Background(), "TRUNCATE auth.user CASCADE"))

	return mgr
}
