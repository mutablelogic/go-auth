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

package bitwarden

import (
	"context"
	"os"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// Test_Live reads from a real Bitwarden Secrets Manager, with the access
// token from BWS_ACCESS_TOKEN, and the server from BWS_SERVER_URL. It only
// runs when GOAUTH_TEST_BITWARDEN_LIVE is set, and doesn't change anything.
// It logs counts, but not secret keys or values.
func Test_Live(t *testing.T) {
	if os.Getenv("GOAUTH_TEST_BITWARDEN_LIVE") == "" {
		t.Skip("set GOAUTH_TEST_BITWARDEN_LIVE and BWS_ACCESS_TOKEN to test against Bitwarden")
	}
	ctx := context.Background()
	mgr, err := New()
	require.NoError(t, err)

	// Logging in decrypts the organization's key, and listing decrypts the
	// keys of the secrets
	index, err := mgr.index(ctx)
	require.NoError(t, err)
	secrets := 0
	for _, ids := range index {
		secrets += len(ids)
	}
	t.Logf("organization %s: %d secrets, %d keys", mgr.client.orgID, secrets, len(index))

	// Reading a secret decrypts its value
	for key, ids := range index {
		s, err := mgr.client.getSecret(ctx, ids[0])
		require.NoError(t, err)
		assert.Equal(t, key, s.Key)
		t.Logf("read a secret: %d byte value, in %d projects", len(s.Value), len(s.ProjectIDs))
		break
	}

	// A key which doesn't exist isn't found
	_, err = mgr.Get(ctx, "GOAUTH_LIVE_CHECK_MISSING")
	assert.ErrorIs(t, err, auth.ErrNotFound)
}
