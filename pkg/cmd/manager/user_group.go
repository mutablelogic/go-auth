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
	schema "github.com/djthorpe/go-auth/schema/auth"
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
