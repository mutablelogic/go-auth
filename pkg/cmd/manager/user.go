// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
