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
