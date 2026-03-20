package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
	authschema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	require "github.com/stretchr/testify/require"
)

func TestClientDeleteMethods(t *testing.T) {
	t.Run("DeleteUserHandlesNoContent", func(t *testing.T) {
		require := require.New(t)
		userID := authschema.UserID(uuid.New())

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodDelete, r.Method)
			require.Equal("/user/"+uuid.UUID(userID).String(), r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		require.NoError(client.DeleteUser(context.Background(), userID))
	})

	t.Run("DeleteGroupHandlesNoContent", func(t *testing.T) {
		require := require.New(t)
		groupID := "delete-group"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodDelete, r.Method)
			require.Equal("/group/"+groupID, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		require.NoError(client.DeleteGroup(context.Background(), groupID))
	})
}
