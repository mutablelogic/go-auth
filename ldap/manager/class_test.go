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
	"sort"
	"strings"
	"testing"

	// Packages
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_SchemaParses(t *testing.T) {
	// Every definition each directory has parses, which checks ldap/parser
	// against real schemas, and the lists have them all
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		classes, attrs := test.Subschema(t, server)
		require.NotEmpty(t, classes)
		require.NotEmpty(t, attrs)
		for _, definition := range classes {
			_, err := schema.ParseObjectClass(definition)
			assert.NoError(t, err, definition)
		}
		for _, definition := range attrs {
			_, err := schema.ParseAttributeType(definition)
			assert.NoError(t, err, definition)
		}

		listedClasses, err := m.ListObjectClasses(ctx, schema.ObjectClassListRequest{})
		require.NoError(t, err)
		assert.Equal(t, uint64(len(classes)), listedClasses.Count)
		listedAttrs, err := m.ListAttributeTypes(ctx, schema.AttributeTypeListRequest{})
		require.NoError(t, err)
		assert.Equal(t, uint64(len(attrs)), listedAttrs.Count)
	})
}

func Test_ListObjectClasses(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		// By name, from the offset, up to the limit
		all, err := m.ListObjectClasses(ctx, schema.ObjectClassListRequest{})
		require.NoError(t, err)
		require.NotEmpty(t, all.Body)
		names := []string{}
		for _, class := range all.Body {
			names = append(names, strings.ToLower(class.Identifier()))
		}
		assert.True(t, sort.StringsAreSorted(names), "by name")

		page, err := m.ListObjectClasses(ctx, schema.ObjectClassListRequest{OffsetLimit: schema.OffsetLimit{Offset: 2, Limit: types.Ptr(uint64(3))}})
		require.NoError(t, err)
		assert.Equal(t, all.Count, page.Count)
		require.Len(t, page.Body, 3)
		assert.Equal(t, all.Body[2].Identifier(), page.Body[0].Identifier())

		// By name, which every directory has
		person, err := m.ListObjectClasses(ctx, schema.ObjectClassListRequest{Filter: types.Ptr("person")})
		require.NoError(t, err)
		require.NotEmpty(t, person.Body)
		assert.Equal(t, "person", person.Body[0].Identifier())
		assert.Equal(t, schema.ObjectClassKindStructural, schema.ObjectClassKind(person.Body[0].ClassKind))
		assert.Contains(t, person.Body[0].SuperClasses, "top")

		// By kind
		auxiliary, err := m.ListObjectClasses(ctx, schema.ObjectClassListRequest{Kind: types.Ptr(schema.ObjectClassKindAuxiliary)})
		require.NoError(t, err)
		assert.NotZero(t, auxiliary.Count)
		assert.Less(t, auxiliary.Count, all.Count)
		for _, class := range auxiliary.Body {
			assert.Equal(t, schema.ObjectClassKindAuxiliary, schema.ObjectClassKind(class.ClassKind), class.Identifier())
		}
	})
}

func Test_ListAttributeTypes(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		all, err := m.ListAttributeTypes(ctx, schema.AttributeTypeListRequest{})
		require.NoError(t, err)
		require.NotEmpty(t, all.Body)

		cn, err := m.ListAttributeTypes(ctx, schema.AttributeTypeListRequest{Filter: types.Ptr("cn")})
		require.NoError(t, err)
		require.NotEmpty(t, cn.Body)
		found := false
		for _, attr := range cn.Body {
			found = found || strings.EqualFold(attr.Identifier(), "cn")
		}
		assert.True(t, found, "cn")

		// Each attribute has one usage, which is for user applications when
		// it has none, as most do
		total := uint64(0)
		for _, usage := range []schema.AttributeUsage{schema.AttributeUsageUserApplications, schema.AttributeUsageDirectoryOperation, schema.AttributeUsageDistributedOperation, schema.AttributeUsageDSAOperation} {
			list, err := m.ListAttributeTypes(ctx, schema.AttributeTypeListRequest{Usage: types.Ptr(usage)})
			require.NoError(t, err)
			if usage == schema.AttributeUsageUserApplications {
				assert.Greater(t, list.Count, all.Count/2, usage)
			}
			total += list.Count
		}
		assert.Equal(t, all.Count, total)
	})
}

func Test_SchemaCopies(t *testing.T) {
	// Changing what's returned doesn't change the schema the manager keeps
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		person, err := m.ListObjectClasses(ctx, schema.ObjectClassListRequest{Filter: types.Ptr("person")})
		require.NoError(t, err)
		require.NotEmpty(t, person.Body)
		person.Body[0].Name[0] = "changed"
		person.Body[0].ClassKind = "AUXILIARY"
		person.Body[0].Must = append(person.Body[0].Must[:0], "changed")

		again, err := m.ListObjectClasses(ctx, schema.ObjectClassListRequest{Filter: types.Ptr("person")})
		require.NoError(t, err)
		require.NotEmpty(t, again.Body)
		assert.Equal(t, "person", again.Body[0].Identifier())
		assert.Equal(t, schema.ObjectClassKindStructural, schema.ObjectClassKind(again.Body[0].ClassKind))
		assert.NotContains(t, again.Body[0].Must, "changed")

		cn, err := m.ListAttributeTypes(ctx, schema.AttributeTypeListRequest{Filter: types.Ptr("cn")})
		require.NoError(t, err)
		require.NotEmpty(t, cn.Body)
		name := cn.Body[0].Identifier()
		cn.Body[0].Name[0] = "changed"
		again2, err := m.ListAttributeTypes(ctx, schema.AttributeTypeListRequest{Filter: types.Ptr("cn")})
		require.NoError(t, err)
		require.NotEmpty(t, again2.Body)
		assert.Equal(t, name, again2.Body[0].Identifier())
	})
}
