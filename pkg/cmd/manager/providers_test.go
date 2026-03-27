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

package manager

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	require "github.com/stretchr/testify/require"
)

func TestProvidersCommandPrintsConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"google":{"issuer":"https://accounts.google.com","client_id":"google-client-id"},"local":{"issuer":"http://localhost:8084/api"}}`))
	}))
	defer server.Close()

	cmd := newFakeCmd(server.URL)
	output := new(bytes.Buffer)
	original := providersOutput
	providersOutput = output
	t.Cleanup(func() {
		providersOutput = original
	})

	err := (&ProvidersCommand{}).Run(cmd)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"google": {
			"issuer": "https://accounts.google.com",
			"client_id": "google-client-id"
		},
		"local": {
			"issuer": "http://localhost:8084/api"
		}
	}`, output.String())
}
