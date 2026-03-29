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
	"net/url"
	"testing"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestUpdateTargetDN(t *testing.T) {
	t.Run("RenamesWhenNamingAttributeChanges", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		dn, err := schema.NewDN("uid=s,ou=users,dc=example,dc=com")
		require.NoError(err)

		currentDN, targetDN, newRDN, rename, err := updateTargetDN(dn, url.Values{"uid": {"sam"}})

		require.NoError(err)
		assert.True(rename)
		assert.Equal("uid=s,ou=users,dc=example,dc=com", currentDN)
		assert.Equal("uid=sam", newRDN)
		assert.Equal("uid=sam,ou=users,dc=example,dc=com", targetDN)
	})

	t.Run("KeepsDNWhenNamingAttributeUnchanged", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		dn, err := schema.NewDN("uid=s,ou=users,dc=example,dc=com")
		require.NoError(err)

		currentDN, targetDN, newRDN, rename, err := updateTargetDN(dn, url.Values{"cn": {"Sam"}})

		require.NoError(err)
		assert.False(rename)
		assert.Equal(currentDN, targetDN)
		assert.Empty(newRDN)
	})

	t.Run("RejectsDeletingNamingAttribute", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		dn, err := schema.NewDN("uid=s,ou=users,dc=example,dc=com")
		require.NoError(err)

		_, _, _, _, err = updateTargetDN(dn, url.Values{"uid": nil})

		require.Error(err)
		assert.Contains(err.Error(), "naming attribute \"uid\" cannot be deleted")
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
	})

	t.Run("ModifyRequestSkipsRDNAttributesAfterRename", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		dn, err := schema.NewDN("cn=eng,ou=groups,dc=example,dc=com")
		require.NoError(err)

		modifyReq, hasChanges := newModifyRequest("cn=eng2,ou=groups,dc=example,dc=com", url.Values{
			"cn":          {"eng2"},
			"description": {"Engineering"},
		}, dn, true)

		assert.True(hasChanges)
		require.Len(modifyReq.Changes, 1)
		assert.Equal("description", modifyReq.Changes[0].Modification.Type)
	})

	t.Run("ModifyRequestCanBeEmptyAfterRename", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		dn, err := schema.NewDN("cn=alice,ou=users,dc=example,dc=com")
		require.NoError(err)

		modifyReq, hasChanges := newModifyRequest("cn=alice2,ou=users,dc=example,dc=com", url.Values{
			"cn": {"alice2"},
		}, dn, true)

		assert.False(hasChanges)
		assert.Empty(modifyReq.Changes)
	})
}
