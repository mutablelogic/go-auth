package auth

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Commands struct {
	Authorize AuthorizeCommand `cmd:"" help:"Authorize to a provider and save the resulting token for future use." group:"AUTH"`
	Refresh   RefreshCommand   `cmd:"" help:"Refresh a stored OAuth token for an endpoint." group:"AUTH"`
	Revoke    RevokeCommand    `cmd:"" help:"Revoke and remove a stored OAuth token for an endpoint." group:"AUTH"`
	UserInfo  UserInfoCommand  `cmd:"" name:"userinfo" help:"Fetch userinfo using the stored OAuth token for an endpoint." group:"AUTH"`
}
