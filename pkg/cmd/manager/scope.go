package manager

import (
	"fmt"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/httpclient/manager"
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ScopeCommands struct {
	Scopes ListScopesCommand `cmd:"" name:"scopes" help:"Get Scopes." group:"USERS & GROUPS"`
}

type ListScopesCommand struct {
	schema.ScopeListRequest
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListScopesCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		scopes, err := manager.ListScopes(ctx.Context(), cmd.ScopeListRequest)
		if err != nil {
			return err
		}
		fmt.Println(scopes)
		return nil
	})
}
