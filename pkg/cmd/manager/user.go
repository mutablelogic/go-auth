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

type UserCommands struct {
	Users      ListUsersCommand  `cmd:"" name:"users" help:"Get Users." group:"USER MANAGER"`
	User       GetUserCommand    `cmd:"" name:"user" help:"Get User." group:"USER MANAGER"`
	UpdateUser UpdateUserCommand `cmd:"" name:"user-update" help:"Update User." group:"USER MANAGER"`
	DeleteUser DeleteUserCommand `cmd:"" name:"user-delete" help:"Delete User." group:"USER MANAGER"`
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

type DeleteUserCommand struct {
	GetUserCommand
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListUsersCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		users, err := manager.ListUsers(ctx.Context(), cmd.UserListRequest)
		if err != nil {
			return err
		}
		fmt.Println(users)
		return nil
	})
}

func (cmd *GetUserCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		user, err := manager.GetUser(ctx.Context(), cmd.UserID)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *UpdateUserCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		user, err := manager.UpdateUser(ctx.Context(), cmd.UserID, cmd.UserMeta)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *DeleteUserCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		if err := manager.DeleteUser(ctx.Context(), cmd.UserID); err != nil {
			return err
		}
		fmt.Println(cmd.UserID)
		return nil
	})
}
