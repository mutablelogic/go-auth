package auth

import (
	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

// clientFor returns auth client configured from the global HTTP flags.
func clientFor(ctx server.Cmd) (*auth.Client, string, error) {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return nil, "", err
	}
	auth, err := auth.New(endpoint, opts...)
	if err != nil {
		return nil, "", err
	}
	return auth, endpoint, nil
}
