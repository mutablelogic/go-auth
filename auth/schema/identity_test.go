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
	schema "github.com/mutablelogic/go-auth/auth/schema"
	assert "github.com/stretchr/testify/assert"
)

func Test_CredentialString(t *testing.T) {
	// A credential's secrets aren't in its string, such as in a log, or a
	// span
	credential := schema.Credential{Code: "the-code", CodeVerifier: "the-verifier", RedirectURL: "http://127.0.0.1/callback", Username: "alice", Password: "the-password"}
	s := credential.String()
	for _, secret := range []string{"the-code", "the-verifier", "the-password"} {
		assert.NotContains(t, s, secret)
	}
	assert.Contains(t, s, "alice")
	assert.Contains(t, s, "http://127.0.0.1/callback")
	assert.Equal(t, "the-password", credential.Password, "the credential itself isn't changed")
}

func Test_OAuthClientString(t *testing.T) {
	client := schema.OAuthClient{ClientID: "the-id", ClientSecret: "the-secret"}
	assert.NotContains(t, client.String(), "the-secret")
	assert.Contains(t, client.String(), "the-id")
}
