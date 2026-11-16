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

package httphandler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	// Packages
	httphandler "github.com/mutablelogic/go-auth/ldap/httphandler"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	ldaptest "github.com/mutablelogic/go-auth/ldap/test"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	openapischema "github.com/mutablelogic/go-server/pkg/openapi/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	ldaptest.Main(m)
}

// newServer returns a server of a manager whose users and groups are in
// organizational units of the test's
func newServer(t *testing.T, ctx context.Context, server ldaptest.Server, m *manager.Manager) *test.Server {
	t.Helper()
	mgr := ldaptest.Manager(t, ctx, server, manager.WithUserDN(ldaptest.OU(t, ctx, m)), manager.WithGroupDN(ldaptest.OU(t, ctx, m)))
	return test.NewServer(t, httphandler.RegisterHandlers(mgr, false))
}

// userAttrs returns a user's attributes, with the password
func userAttrs(name, password string) schema.ObjectPutRequest {
	return schema.ObjectPutRequest{Attrs: schema.Attrs{
		"cn":            {name + " Example"},
		"sn":            {"Example"},
		"userPassword":  {password},
		"homeDirectory": {"/home/" + name},
	}}
}

func Test_Schema(t *testing.T) {
	ldaptest.ForEach(t, func(t *testing.T, ctx context.Context, server ldaptest.Server, m *manager.Manager) {
		s := newServer(t, ctx, server, m)

		var classes schema.ObjectClassListResponse
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/class?filter=person", nil, &classes))
		require.NotEmpty(t, classes.Body)
		assert.Equal(t, "person", classes.Body[0].Identifier())

		var attrs schema.AttributeTypeListResponse
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/attr?usage=userApplications&limit=5", nil, &attrs))
		assert.Len(t, attrs.Body, 5)
		assert.Greater(t, attrs.Count, uint64(5))

		status, _ := s.Do(t, http.MethodGet, "ldap/class?limit=x", nil)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

func Test_Users(t *testing.T) {
	ldaptest.ForEach(t, func(t *testing.T, ctx context.Context, server ldaptest.Server, m *manager.Manager) {
		s := newServer(t, ctx, server, m)

		var user schema.Object
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPut, "ldap/user/alice?allocate_gid=true", userAttrs("alice", "first Passw0rd!"), &user))
		assert.NotNil(t, user.Get("uidNumber"))
		assert.Equal(t, user.Get("uidNumber"), user.Get("gidNumber"))

		var got schema.Object
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/user/alice", nil, &got))
		assert.Equal(t, user.DN, got.DN)
		var list schema.ObjectList
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/user", nil, &list))
		assert.Equal(t, uint64(1), list.Count)

		naming := "uid"
		if server.ActiveDirectory {
			naming = "cn"
		}
		var updated schema.Object
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPatch, "ldap/user/alice", schema.ObjectPutRequest{Attrs: schema.Attrs{naming: {"alicia"}, "description": {"Renamed"}}}, &updated))
		assert.Equal(t, types.Ptr("Renamed"), updated.Get("description"))

		status, _ := s.Do(t, http.MethodGet, "ldap/user/alice", nil)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = s.Do(t, http.MethodPut, "ldap/user/alicia?allocate_gid=true", userAttrs("alicia", "first Passw0rd!"))
		assert.Equal(t, http.StatusConflict, status)
		status, _ = s.Do(t, http.MethodPut, "ldap/user/bob?allocate_gid=x", nil)
		assert.Equal(t, http.StatusBadRequest, status)

		var deleted schema.Object
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodDelete, "ldap/user/alicia", nil, &deleted))
		assert.Equal(t, updated.DN, deleted.DN)
		status, _ = s.Do(t, http.MethodDelete, "ldap/user/alicia", nil)
		assert.Equal(t, http.StatusNotFound, status)
	})
}

func Test_Groups(t *testing.T) {
	ldaptest.ForEach(t, func(t *testing.T, ctx context.Context, server ldaptest.Server, m *manager.Manager) {
		s := newServer(t, ctx, server, m)
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPut, "ldap/user/alice?allocate_gid=true", userAttrs("alice", "first Passw0rd!"), nil))

		// Without attributes
		var group schema.Object
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPut, "ldap/group/eng", schema.ObjectPutRequest{}, &group))
		assert.Equal(t, types.Ptr("eng"), group.Get("cn"))

		// Members
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPost, "ldap/group/eng/user", []string{"alice"}, nil))
		var list schema.ObjectList
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/user?group=eng", nil, &list))
		assert.Equal(t, uint64(1), list.Count)
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/group?user=alice", nil, &list))
		assert.Equal(t, uint64(1), list.Count)
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodDelete, "ldap/group/eng/user", []string{"alice"}, nil))
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/user?group=eng", nil, &list))
		assert.Zero(t, list.Count)

		status, _ := s.Do(t, http.MethodPost, "ldap/group/eng/user", []string{"missing"})
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = s.Do(t, http.MethodPost, "ldap/group/eng/user", []string{})
		assert.Equal(t, http.StatusBadRequest, status)
		status, _ = s.Do(t, http.MethodGet, "ldap/user?group=missing", nil)
		assert.Equal(t, http.StatusNotFound, status)

		// Rename, and delete
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPatch, "ldap/group/eng", schema.ObjectPutRequest{Attrs: schema.Attrs{"cn": {"engineering"}}}, nil))
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/group/engineering", nil, nil))
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodDelete, "ldap/group/engineering", nil, nil))
		status, _ = s.Do(t, http.MethodGet, "ldap/group/engineering", nil)
		assert.Equal(t, http.StatusNotFound, status)
	})
}

func Test_Objects(t *testing.T) {
	ldaptest.ForEach(t, func(t *testing.T, ctx context.Context, server ldaptest.Server, m *manager.Manager) {
		s := newServer(t, ctx, server, m)
		ou := ldaptest.OU(t, ctx, m)
		dn := "ou=a," + ou

		// A DN as it is, and escaped
		unit := schema.ObjectPutRequest{Attrs: schema.Attrs{"objectClass": {"top", "organizationalUnit"}, "ou": {"a"}}}
		var object schema.Object
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPut, "ldap/object/"+dn, unit, &object))
		assert.True(t, strings.EqualFold(dn, object.DN))
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/object/"+strings.ReplaceAll(dn, ",", "%2C"), nil, nil), "escaped")
		status, _ := s.Do(t, http.MethodGet, "ldap/object/"+strings.ReplaceAll(dn, ",", "%252C"), nil)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, status, "escaped twice")
		status, _ = s.Do(t, http.MethodPut, "ldap/object/"+dn, unit)
		assert.Equal(t, http.StatusConflict, status)

		var list schema.ObjectList
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "ldap/object?prefix="+url.QueryEscape(ou), nil, &list))
		assert.Equal(t, uint64(2), list.Count)
		status, _ = s.Do(t, http.MethodGet, "ldap/object?prefix="+url.QueryEscape("ou=missing,"+ou), nil)
		assert.Equal(t, http.StatusNotFound, status)

		var updated schema.Object
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPatch, "ldap/object/"+dn, schema.ObjectPutRequest{Attrs: schema.Attrs{"description": {" Spaced "}}}, &updated))
		assert.Equal(t, types.Ptr(" Spaced "), updated.Get("description"))

		// Bind, and passwords, as a user
		var user schema.Object
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPut, "ldap/user/bob?allocate_gid=true", userAttrs("bob", "first Passw0rd!"), &user))
		path := "ldap/object/" + url.PathEscape(user.DN)
		status, _ = s.DoWithContentType(t, http.MethodPost, path+"/bind", types.ContentTypeTextPlain, "first Passw0rd!")
		assert.Equal(t, http.StatusOK, status)
		status, _ = s.DoWithContentType(t, http.MethodPost, path+"/bind", types.ContentTypeTextPlain, "wrong Passw0rd!")
		assert.Equal(t, http.StatusUnauthorized, status)

		var response schema.PasswordResponse
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPost, path+"/password", schema.ObjectPasswordRequest{Old: "first Passw0rd!"}, &response))
		require.NotEmpty(t, response.GeneratedPassword)
		status, _ = s.DoWithContentType(t, http.MethodPost, path+"/bind", types.ContentTypeTextPlain, response.GeneratedPassword)
		assert.Equal(t, http.StatusOK, status)
		status, _ = s.Do(t, http.MethodPost, path+"/password", schema.ObjectPasswordRequest{Old: "wrong Passw0rd!"})
		assert.Equal(t, http.StatusUnauthorized, status)

		// Delete
		status, _ = s.Do(t, http.MethodDelete, "ldap/object/"+ou, nil)
		assert.Equal(t, http.StatusConflict, status, "it has children")
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodDelete, "ldap/object/"+dn, nil, nil))
		status, _ = s.Do(t, http.MethodGet, "ldap/object/"+dn, nil)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = s.Do(t, http.MethodGet, "ldap/object/not%20a%20dn", nil)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

func Test_Auth(t *testing.T) {
	// The scopes are checked before the manager, which isn't connected
	mgr, err := manager.New(manager.WithUrl("ldap://admin@localhost"), manager.WithBaseDN("dc=example,dc=test"))
	require.NoError(t, err)

	// With auth, the operations need a registered security scheme
	router, err := httprouter.NewRouter(context.Background(), http.NewServeMux(), "/api", "", "test", "0.0.0")
	require.NoError(t, err)
	assert.Error(t, httphandler.RegisterHandlers(mgr, true)(router))

	// With one, which grants the scopes in a header, reading needs
	// ldap:read, and changing, binding and passwords ldap:write
	mux := http.NewServeMux()
	router, err = httprouter.NewRouter(context.Background(), mux, "/api", "", "test", "0.0.0")
	require.NoError(t, err)
	require.NoError(t, router.RegisterSecurityScheme("bearerAuth", scopeScheme{}))
	require.NoError(t, httphandler.RegisterHandlers(mgr, true)(router))
	server := httptest.NewServer(mux)
	defer server.Close()

	do := func(method, path string, scopes ...string) int {
		req, err := http.NewRequest(method, server.URL+"/api/"+path, strings.NewReader("{}"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scopes", strings.Join(scopes, ","))
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.StatusCode
	}
	for _, path := range []string{"ldap/class", "ldap/attr", "ldap/user", "ldap/user/a", "ldap/group", "ldap/group/a", "ldap/object", "ldap/object/ou=a"} {
		assert.Equal(t, http.StatusForbidden, do(http.MethodGet, path), path)
		assert.NotEqual(t, http.StatusForbidden, do(http.MethodGet, path, schema.ScopeLDAPRead), path)
	}
	for _, op := range [][2]string{{http.MethodPut, "ldap/user/a"}, {http.MethodPatch, "ldap/group/a"}, {http.MethodDelete, "ldap/object/ou=a"}, {http.MethodPost, "ldap/object/ou=a/bind"}, {http.MethodPost, "ldap/object/ou=a/password"}, {http.MethodPost, "ldap/group/a/user"}} {
		assert.Equal(t, http.StatusForbidden, do(op[0], op[1], schema.ScopeLDAPRead), op)
		assert.NotEqual(t, http.StatusForbidden, do(op[0], op[1], schema.ScopeLDAPWrite), op)
	}
}

// scopeScheme grants the scopes in the X-Scopes header
type scopeScheme struct{}

func (scopeScheme) Spec() openapischema.SecurityScheme {
	return openapischema.SecurityScheme{Type: "http", Scheme: "bearer"}
}

func (scopeScheme) Wrap(handler http.HandlerFunc, scopes []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		granted := strings.Split(r.Header.Get("X-Scopes"), ",")
		for _, scope := range scopes {
			if !slices.Contains(granted, scope) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		handler(w, r)
	}
}
