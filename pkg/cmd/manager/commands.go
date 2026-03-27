package manager

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ManagerCommands struct {
	Providers ProvidersCommand `cmd:"" help:"Print the configured identity providers." group:"USER MANAGER"`
	Login     LoginCommand     `cmd:"" help:"Login to a provider." group:"USER MANAGER"`
	UserCommands
	UserGroupCommands
	GroupCommands
	ScopeCommands
	ChangesCommands
}
