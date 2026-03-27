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

package schema_test

import (
	"testing"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	assert "github.com/stretchr/testify/assert"
)

func Test_DN_001(t *testing.T) {
	assert := assert.New(t)

	// Check new DN
	dn, err := schema.NewDN("cn=John Doe,dc=example,dc=com")
	assert.NoError(err)
	assert.NotNil(dn)
	assert.Equal("cn=John Doe,dc=example,dc=com", dn.String())
}

func Test_DN_002(t *testing.T) {
	assert := assert.New(t)

	// Setup
	bdn, err := schema.NewDN("ou=users,dc=example,dc=com")
	assert.NoError(err)

	rdn, err := schema.NewDN("cn=John Doe")
	assert.NoError(err)

	dn := rdn.Join(bdn)
	assert.NotNil(dn)
	assert.Equal("cn=John Doe,ou=users,dc=example,dc=com", dn.String())

	// Check ancestor
	assert.True(bdn.AncestorOf(dn))

}
