package manager

import (
	"net/http"

	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	manager "github.com/djthorpe/go-auth/pkg/httpclient/manager"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

// WithClient returns auth client configured from the global HTTP flags.
func WithClient(ctx server.Cmd, fn func(*manager.Client, string) error) error {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	authClient, err := auth.New(endpoint, opts...)
	if err != nil {
		return err
	}
	opts = append(opts, client.OptTransport(func(parent http.RoundTripper) http.RoundTripper {
		return newAuthTransport(parent, ctx, endpoint, authClient)
	}))
	client, err := manager.New(endpoint, opts...)
	if err != nil {
		return err
	}
	return fn(client, endpoint)
}
