package auth

import (
	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthCommands struct {
	Authorize AuthorizeCommand `cmd:"" help:"Authorize to a provider and save the resulting token for future use." group:"AUTH"`
	Refresh   RefreshCommand   `cmd:"" help:"Refresh a stored OAuth token for an endpoint." group:"AUTH"`
	Revoke    RevokeCommand    `cmd:"" help:"Revoke and remove a stored OAuth token for an endpoint." group:"AUTH"`
	UserInfo  UserInfoCommand  `cmd:"" name:"userinfo" help:"Fetch userinfo using the stored OAuth token for an endpoint." group:"AUTH"`
}

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
