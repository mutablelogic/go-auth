package main

import (
	"fmt"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

type ScopeCommands struct {
	Scopes ListScopesCommand `cmd:"" name:"scopes" help:"Get Scopes." group:"USERS & GROUPS"`
}

type ListScopesCommand struct {
	schema.ScopeListRequest
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListScopesCommand) Run(ctx server.Cmd) error {
	clients, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	scopes, err := clients.manager.ListScopes(ctx.Context(), cmd.ScopeListRequest)
	if err != nil {
		return err
	}
	fmt.Println(scopes)
	return nil
}
