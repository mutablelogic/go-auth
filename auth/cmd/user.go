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
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	// Packages
	authpkg "github.com/mutablelogic/go-auth"
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
	NoExpiresAt bool `name:"no-expires-at" help:"Remove the user expiry instead of setting one."`
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

func (cmd *ListUsersCommand) Run(globals server.Cmd) error {
	return withManager(globals, "ListUsersCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		users, err := client.ListUsers(ctx, cmd.UserListRequest)
		if err != nil {
			return err
		}

		// Convert into a table
		userRows := make([]userRow, len(users.Body))
		for i, user := range users.Body {
			userRows[i] = userRow(user)
		}

		// Write out the user table, and the summary
		tui.TableFor[userRow](tui.SetWidth(globals.IsTerm())).Write(os.Stdout, userRows...)
		tui.TableSummary("users", users.Count, users.Offset, users.Limit).Write(os.Stdout)

		// Return success
		return nil

	})
}

func (cmd *GetUserCommand) Run(globals server.Cmd) error {
	return withManager(globals, "GetUserCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		user, err := client.GetUser(ctx, cmd.ID)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *UpdateUserCommand) Run(globals server.Cmd) error {
	return withManager(globals, "UpdateUserCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		if cmd.NoExpiresAt {
			if cmd.ExpiresAt != nil {
				return authpkg.ErrBadParameter.With("cannot use --no-expires-at with --expires-at")
			} else {
				cmd.ExpiresAt = types.Ptr(time.Time{})
			}
		}

		user, err := client.UpdateUser(ctx, cmd.ID, cmd.UserMeta)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *DeleteUserCommand) Run(globals server.Cmd) error {
	return withManager(globals, "DeleteUserCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		if err := client.DeleteUser(ctx, cmd.ID); err != nil {
			return err
		}
		return nil
	})
}

func (cmd *JoinGroupsCommand) Run(globals server.Cmd) error {
	return withManager(globals, "JoinGroupsCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		user, err := client.AddUserGroups(ctx, cmd.ID, cmd.Groups)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

func (cmd *LeaveGroupsCommand) Run(globals server.Cmd) error {
	return withManager(globals, "LeaveGroupsCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		user, err := client.RemoveUserGroups(ctx, cmd.ID, cmd.Groups)
		if err != nil {
			return err
		}
		fmt.Println(user)
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// TABLE OUTPUT

type userRow schema.User

func (r userRow) Header() []string {
	return []string{"User", "UUID", "Groups", "Scopes", "Status"}
}

func (r userRow) Cell(i int) string {
	switch i {
	case 0:
		if r.Name == "" && r.Email != "" {
			return r.Email
		}
		if r.Email != "" && r.Name == "" {
			return r.Email
		}
		return fmt.Sprintf("%s <%s>", r.Name, r.Email)
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
