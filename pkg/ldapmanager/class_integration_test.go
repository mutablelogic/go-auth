//go:build integration

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

package ldap

import (
	"context"
	"strings"
	"testing"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestLDAPSchemaIntegration(t *testing.T) {
	forEachLDAPIntegrationServer(t, func(t *testing.T, ctx context.Context, server ldapIntegrationServer, manager *Manager) {
		classes, err := manager.ListObjectClasses(ctx, schema.ObjectClassListRequest{})
		require.NoError(t, err)
		require.NotNil(t, classes)
		assert.NotZero(t, classes.Count)
		require.NotEmpty(t, classes.Body)

		userClass := manager.users.ObjectClass[0]
		classes, err = manager.ListObjectClasses(ctx, schema.ObjectClassListRequest{Filter: &userClass})
		require.NoError(t, err)
		require.NotNil(t, classes)
		assert.NotZero(t, classes.Count)
		assert.True(t, objectClassListContains(classes.Body, userClass))

		attribute := "cn"
		attributes, err := manager.ListAttributeTypes(ctx, schema.AttributeTypeListRequest{Filter: &attribute})
		require.NoError(t, err)
		require.NotNil(t, attributes)
		assert.NotZero(t, attributes.Count)
		assert.True(t, attributeTypeListContains(attributes.Body, attribute))

		assert.NotEmpty(t, manager.users.ObjectClass)
		assert.NotEmpty(t, manager.groups.ObjectClass)
	})
}

func objectClassListContains(classes []*schema.ObjectClass, name string) bool {
	for _, class := range classes {
		if class != nil && strings.EqualFold(class.Identifier(), name) {
			return true
		}
	}
	return false
}

func attributeTypeListContains(attributes []*schema.AttributeType, name string) bool {
	for _, attribute := range attributes {
		if attribute != nil && strings.EqualFold(attribute.Identifier(), name) {
			return true
		}
	}
	return false
}
