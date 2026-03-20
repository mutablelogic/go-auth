package main

import (
	// Packages
	"fmt"

	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

type UserGroupCommands struct {
	UserJoin  AddUserGroupsCommand    `cmd:"" name:"user-join" help:"Add user to groups." group:"USERS & GROUPS"`
	UserLeave RemoveUserGroupsCommand `cmd:"" name:"user-leave" help:"Remove user from groups." group:"USERS & GROUPS"`
}

type AddUserGroupsCommand struct {
	GetUserCommand
	Groups schema.UserGroupList `arg:"" name:"groups" help:"Groups for user the join"`
}

type RemoveUserGroupsCommand struct {
	GetUserCommand
	Groups schema.UserGroupList `arg:"" name:"groups" help:"Groups for user the leave"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *AddUserGroupsCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	user, err := client.AddUserGroups(ctx.Context(), cmd.UserID, cmd.Groups)
	if err != nil {
		return err
	}
	fmt.Println(user)
	return nil
}

func (cmd *RemoveUserGroupsCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	user, err := client.RemoveUserGroups(ctx.Context(), cmd.UserID, cmd.Groups)
	if err != nil {
		return err
	}
	fmt.Println(user)
	return nil
}
