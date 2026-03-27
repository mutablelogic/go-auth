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

type UserGroupCommands struct {
	UserJoin  AddUserGroupsCommand    `cmd:"" name:"user-join" help:"Add user to groups." group:"USER MANAGER"`
	UserLeave RemoveUserGroupsCommand `cmd:"" name:"user-leave" help:"Remove user from groups." group:"USER MANAGER"`
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
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		user, err := manager.AddUserGroups(ctx.Context(), cmd.UserID, cmd.Groups)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *RemoveUserGroupsCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		user, err := manager.RemoveUserGroups(ctx.Context(), cmd.UserID, cmd.Groups)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}
