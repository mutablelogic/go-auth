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

package auth

import (
	"fmt"
	"os"
	"strings"

	// Packages

	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	server "github.com/mutablelogic/go-server"
	tui "github.com/mutablelogic/go-server/pkg/tui"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type UserCommands struct {
	Users       ListUsersCommand   `cmd:"" name:"users" help:"Get Users." group:"AUTH MANAGER"`
	User        GetUserCommand     `cmd:"" name:"user" help:"Get User." group:"AUTH MANAGER"`
	UpdateUser  UpdateUserCommand  `cmd:"" name:"user-update" help:"Update User." group:"AUTH MANAGER"`
	DeleteUser  DeleteUserCommand  `cmd:"" name:"user-delete" help:"Delete User." group:"AUTH MANAGER"`
	JoinGroups  JoinGroupsCommand  `cmd:"" name:"user-join" help:"Add user to groups." group:"AUTH MANAGER"`
	LeaveGroups LeaveGroupsCommand `cmd:"" name:"user-leave" help:"Remove user from groups." group:"AUTH MANAGER"`
}

type ListUsersCommand struct {
	schema.UserListRequest
}

type GetUserCommand struct {
	ID schema.UserID `arg:"" name:"user" help:"User UUID"`
}

type UpdateUserCommand struct {
	GetUserCommand
	schema.UserMeta
}

type DeleteUserCommand struct {
	GetUserCommand
}

type JoinGroupsCommand struct {
	GetUserCommand
	Groups []string `arg:"" name:"groups" help:"Groups to add user to."`
}

type LeaveGroupsCommand struct {
	GetUserCommand
	Groups []string `arg:"" name:"groups" help:"Groups to remove user from."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListUsersCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		users, err := client.ListUsers(ctx.Context(), cmd.UserListRequest)
		if err != nil {
			return err
		}

		// Convert into a table
		userRows := make([]userRow, len(users.Body))
		for i, user := range users.Body {
			userRows[i] = userRow(user)
		}

		// Write out the user table, and the summary
		tui.TableFor[userRow](tui.SetWidth(ctx.IsTerm())).Write(os.Stdout, userRows...)
		tui.TableSummary("users", users.Count, users.Offset, users.Limit).Write(os.Stdout)

		// Return success
		return nil

	})
}

func (cmd *GetUserCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		user, err := client.GetUser(ctx.Context(), cmd.ID)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *UpdateUserCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		user, err := client.UpdateUser(ctx.Context(), cmd.ID, cmd.UserMeta)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *DeleteUserCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		if err := client.DeleteUser(ctx.Context(), cmd.ID); err != nil {
			return err
		}
		return nil
	})
}

func (cmd *JoinGroupsCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		user, err := client.AddUserGroups(ctx.Context(), cmd.ID, cmd.Groups)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *LeaveGroupsCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		user, err := client.RemoveUserGroups(ctx.Context(), cmd.ID, cmd.Groups)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// TABLES

type userRow schema.User

func (r userRow) Header() []string {
	return []string{"User", "UUID", "Groups", "Scopes", "Status"}
}

func (r userRow) Cell(i int) string {
	switch i {
	case 0:
		return r.Name
	case 1:
		return r.ID.String()
	case 2:
		return strings.Join(r.Groups, ", ")
	case 3:
		return strings.Join(r.Scopes, ", ")
	case 4:
		return string(types.Value(r.Status))
	default:
		return ""
	}
}

func (r userRow) Width(i int) int {
	return 0
}
