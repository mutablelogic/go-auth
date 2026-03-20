package main

import (
	"fmt"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

type UserCommands struct {
	Users ListUsersCommand `cmd:"" name:"users" help:"Get Users." group:"USERS"`
}

type ListUsersCommand struct {
	schema.UserListRequest
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListUsersCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	users, err := client.ListUsers(ctx.Context(), cmd.UserListRequest)
	if err != nil {
		return err
	}
	fmt.Println(users)
	return nil
}
