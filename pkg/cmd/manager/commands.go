package manager

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ManagerCommands struct {
	Login LoginCommand `cmd:"" help:"Login to a provider and save the resulting token for future use." group:"USER MANAGER"`
	UserCommands
	UserGroupCommands
	GroupCommands
	ScopeCommands
	ChangesCommands
}
