package main

import (
	"fmt"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

type UserCommands struct {
	Users      ListUsersCommand  `cmd:"" name:"users" help:"Get Users." group:"USERS"`
	User       GetUserCommand    `cmd:"" name:"user" help:"Get User." group:"USERS"`
	UpdateUser UpdateUserCommand `cmd:"" name:"update-user" help:"Update User." group:"USERS"`
}

type ListUsersCommand struct {
	schema.UserListRequest
}

type GetUserCommand struct {
	UserID schema.UserID `arg:"" name:"user" help:"User UUID"`
}

type UpdateUserCommand struct {
	GetUserCommand
	schema.UserMeta
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

func (cmd *GetUserCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	user, err := client.GetUser(ctx.Context(), cmd.UserID)
	if err != nil {
		return err
	}
	fmt.Println(user)
	return nil
}

func (cmd *UpdateUserCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	user, err := client.UpdateUser(ctx.Context(), cmd.UserID, cmd.UserMeta)
	if err != nil {
		return err
	}
	fmt.Println(user)
	return nil
}
