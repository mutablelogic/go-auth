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

package manager_test

import (
	"context"
	"strings"
	"testing"

	// Packages
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// unit returns the attributes of an organizational unit
func unit(name string, attrs ...string) schema.Attrs {
	result := schema.Attrs{"objectClass": {"top", "organizationalUnit"}, "ou": {name}}
	for i := 0; i+1 < len(attrs); i += 2 {
		result[attrs[i]] = append(result[attrs[i]], attrs[i+1])
	}
	return result
}

func Test_Object(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)

		// Create, relative to the base DN
		rel := strings.TrimSuffix(ou, ","+server.BaseDN)
		created, err := m.Create(ctx, "ou=projects,"+rel, unit("projects", "description", "Projects"))
		require.NoError(t, err)
		assert.True(t, strings.EqualFold("ou=projects,"+ou, created.DN), created.DN)
		assert.Equal(t, types.Ptr("Projects"), created.Get("description"))

		// Get, relative or absolute
		got, err := m.Get(ctx, "ou=projects,"+rel)
		require.NoError(t, err)
		assert.Equal(t, created.DN, got.DN)
		got, err = m.Get(ctx, created.DN)
		require.NoError(t, err)
		assert.Equal(t, created.DN, got.DN)

		// List, with a filter
		list, err := m.List(ctx, schema.ObjectListRequest{Filter: types.Ptr("(ou=projects)")})
		require.NoError(t, err)
		assert.NotZero(t, list.Count)
		found := false
		for _, object := range list.Body {
			found = found || object.DN == created.DN
		}
		assert.True(t, found, "listed")

		// Update a value, keeping its spaces
		updated, err := m.Update(ctx, created.DN, schema.Attrs{"description": {" Spaced "}})
		require.NoError(t, err)
		assert.Equal(t, created.DN, updated.DN)
		assert.Equal(t, types.Ptr(" Spaced "), updated.Get("description"))

		// Delete a value, with no values
		updated, err = m.Update(ctx, created.DN, schema.Attrs{"description": nil})
		require.NoError(t, err)
		assert.Nil(t, updated.Get("description"))

		// Rename, by changing the RDN's value, and another attribute
		renamed, err := m.Update(ctx, created.DN, schema.Attrs{"ou": {"archive"}, "description": {"Archive"}})
		require.NoError(t, err)
		assert.True(t, strings.EqualFold("ou=archive,"+ou, renamed.DN), renamed.DN)
		assert.Equal(t, types.Ptr("Archive"), renamed.Get("description"))
		_, err = m.Get(ctx, created.DN)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound, "the old DN is gone")

		// Delete
		deleted, err := m.Delete(ctx, renamed.DN)
		require.NoError(t, err)
		assert.Equal(t, renamed.DN, deleted.DN)
		_, err = m.Get(ctx, renamed.DN)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
	})
}

func Test_ObjectErrors(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)
		_, err := m.Create(ctx, "ou=a,"+ou, unit("a"))
		require.NoError(t, err)
		_, err = m.Create(ctx, "ou=b,ou=a,"+ou, unit("b"))
		require.NoError(t, err)

		_, err = m.Create(ctx, "ou=a,"+ou, unit("a"))
		assert.ErrorIs(t, err, httpresponse.ErrConflict, "already exists")
		_, err = m.Create(ctx, "ou=c,"+ou, schema.Attrs{"ou": {"c"}})
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest, "no objectClass")
		_, err = m.Create(ctx, "ou=c,ou=missing,"+ou, unit("c"))
		assert.ErrorIs(t, err, httpresponse.ErrNotFound, "no parent")
		_, err = m.Create(ctx, "not a dn", unit("c"))
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest, "not a DN")

		_, err = m.Get(ctx, "ou=missing,"+ou)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
		_, err = m.Update(ctx, "ou=missing,"+ou, schema.Attrs{"description": {"x"}})
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
		_, err = m.Update(ctx, "ou=a,"+ou, schema.Attrs{"ou": nil})
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest, "the RDN's attribute")
		_, err = m.Delete(ctx, "ou=missing,"+ou)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
		_, err = m.Delete(ctx, "ou=a,"+ou)
		assert.ErrorIs(t, err, httpresponse.ErrConflict, "has children")

		_, err = m.List(ctx, schema.ObjectListRequest{Filter: types.Ptr("ou=a")})
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest, "a filter without parentheses")
	})
}

func Test_ObjectList(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)
		tag := strings.TrimPrefix(strings.SplitN(ou, ",", 2)[0], "ou=")
		for _, name := range []string{"a", "b", "c"} {
			_, err := m.Create(ctx, "ou="+name+","+ou, unit(name, "description", tag))
			require.NoError(t, err)
		}
		filter := types.Ptr("(description=" + tag + ")")

		// Count is all which match, and the body is from the offset, up to the limit
		list, err := m.List(ctx, schema.ObjectListRequest{Filter: filter})
		require.NoError(t, err)
		assert.Equal(t, uint64(3), list.Count)
		assert.Len(t, list.Body, 3)

		list, err = m.List(ctx, schema.ObjectListRequest{OffsetLimit: schema.OffsetLimit{Offset: 1, Limit: types.Ptr(uint64(1))}, Filter: filter})
		require.NoError(t, err)
		assert.Equal(t, uint64(3), list.Count)
		assert.Len(t, list.Body, 1)

		// Only the attributes asked for
		list, err = m.List(ctx, schema.ObjectListRequest{Filter: filter, Attr: []string{"ou"}})
		require.NoError(t, err)
		require.NotEmpty(t, list.Body)
		assert.NotNil(t, list.Body[0].Get("ou"))
		assert.Nil(t, list.Body[0].Get("description"))
	})
}

func Test_ObjectTrace(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)).Tracer("test")

	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)
		recorder.Reset()
		_, err := m.Create(ctx, "ou=a,"+ou, unit("a", "description", "a secret value"))
		require.NoError(t, err)

		spans := recorder.Ended()
		require.Len(t, spans, 1)
		assert.Equal(t, "ldapmanager.Create", spans[0].Name())
		attrs := map[string]string{}
		for _, attr := range spans[0].Attributes() {
			attrs[string(attr.Key)] = attr.Value.Emit()
		}
		assert.Equal(t, "ou=a,"+ou, attrs["arg.dn"])
		assert.Equal(t, `["description","objectClass","ou"]`, attrs["arg.attrs"])
		for key, value := range attrs {
			assert.NotContains(t, value, "secret", key)
		}
	}, manager.WithTracer(tracer))
}
