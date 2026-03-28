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
	"errors"
	"testing"

	// Packages
	ldapv3 "github.com/go-ldap/ldap/v3"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_manager_001(t *testing.T) {
	t.Run("ClosedConnectionDisconnectErrorsAreIgnored", func(t *testing.T) {
		assert := assert.New(t)

		assert.True(isIgnorableLDAPDisconnectError(&ldapv3.Error{
			ResultCode: ldapv3.ErrorNetwork,
			Err:        errors.New("ldap: connection closed"),
		}))
		assert.True(isIgnorableLDAPDisconnectError(errors.New("ldap: connection closed")))
		assert.False(isIgnorableLDAPDisconnectError(errors.New("some other error")))
	})

	t.Run("LDAPFilterCompileErrorMapsToBadRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		err := ldaperr(&ldapv3.Error{
			ResultCode: ldapv3.ErrorFilterCompile,
			Err:        errors.New("ldap: filter does not start with an '('"),
		})

		require.Error(err)
		assert.Contains(err.Error(), "ldap: filter does not start with an '('")
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
	})

	t.Run("WrappedLDAPFilterCompileErrorMapsToBadRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		err := ldaperr(errors.Join(errors.New("search failed"), &ldapv3.Error{
			ResultCode: ldapv3.ErrorFilterCompile,
			Err:        errors.New("ldap: filter does not start with an '('"),
		}))

		require.Error(err)
		assert.Contains(err.Error(), "ldap: filter does not start with an '('")
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
	})

	t.Run("LDAPInvalidAttributeSyntaxMapsToBadRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		err := ldaperr(&ldapv3.Error{
			ResultCode: ldapv3.LDAPResultInvalidAttributeSyntax,
			Err:        errors.New("objectClass: value #0 invalid per syntax"),
		})

		require.Error(err)
		assert.Contains(err.Error(), "invalid per syntax")
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
	})

	t.Run("LDAPObjectClassViolationMapsToBadRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		err := ldaperr(&ldapv3.Error{
			ResultCode: ldapv3.LDAPResultObjectClassViolation,
			Err:        errors.New("no structural object class provided"),
		})

		require.Error(err)
		assert.Contains(err.Error(), "no structural object class provided")
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
	})

	t.Run("LDAPNamingViolationMapsToBadRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		err := ldaperr(&ldapv3.Error{
			ResultCode: ldapv3.LDAPResultNamingViolation,
			Err:        errors.New("value of naming attribute 'uid' is not present in entry"),
		})

		require.Error(err)
		assert.Contains(err.Error(), "naming attribute 'uid' is not present in entry")
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
	})

	t.Run("LDAPUnwillingToPerformMapsToBadRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		err := ldaperr(&ldapv3.Error{
			ResultCode: ldapv3.LDAPResultUnwillingToPerform,
			Err:        errors.New("unwilling to verify old password"),
		})

		require.Error(err)
		assert.Contains(err.Error(), "unwilling to verify old password")
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
	})
}
