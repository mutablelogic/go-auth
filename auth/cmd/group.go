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
	"strconv"
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

type GroupCommands struct {
	Groups      ListGroupsCommand  `cmd:"" name:"groups" help:"Get Groups." group:"AUTH MANAGER"`
	Group       GetGroupCommand    `cmd:"" name:"group" help:"Get Group." group:"AUTH MANAGER"`
	CreateGroup CreateGroupCommand `cmd:"" name:"group-create" help:"Create Group." group:"AUTH MANAGER"`
	UpdateGroup UpdateGroupCommand `cmd:"" name:"group-update" help:"Update Group." group:"AUTH MANAGER"`
	DeleteGroup DeleteGroupCommand `cmd:"" name:"group-delete" help:"Delete Group." group:"AUTH MANAGER"`
}

type ListGroupsCommand struct {
	schema.GroupListRequest
}

type GetGroupCommand struct {
	Group string `arg:"" name:"group" help:"Group identifier"`
}

type CreateGroupCommand struct {
	GetGroupCommand
	schema.GroupMeta
}

type UpdateGroupCommand struct {
	GetGroupCommand
	schema.GroupMeta
}

type DeleteGroupCommand struct {
	GetGroupCommand
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListGroupsCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		groups, err := client.ListGroups(ctx.Context(), cmd.GroupListRequest)
		if err != nil {
			return err
		}

		// Convert into a table
		groupRows := make([]groupRow, len(groups.Body))
		for i, group := range groups.Body {
			groupRows[i] = groupRow(group)
		}

		// Write out the group table, and the summary
		tui.TableFor[groupRow](tui.SetWidth(ctx.IsTerm())).Write(os.Stdout, groupRows...)
		tui.TableSummary("groups", groups.Count, groups.Offset, groups.Limit).Write(os.Stdout)

		// Return success
		return nil
	})
}

func (cmd *CreateGroupCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		group, err := client.CreateGroup(ctx.Context(), schema.GroupInsert{ID: cmd.Group, GroupMeta: cmd.GroupMeta})
		if err != nil {
			return err
		}
		fmt.Println(group)
		return nil
	})
}

func (cmd *GetGroupCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		group, err := client.GetGroup(ctx.Context(), cmd.Group)
		if err != nil {
			return err
		}
		fmt.Println(group)
		return nil
	})
}

func (cmd *UpdateGroupCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		group, err := client.UpdateGroup(ctx.Context(), cmd.Group, cmd.GroupMeta)
		if err != nil {
			return err
		}
		fmt.Println(group)
		return nil
	})
}

func (cmd *DeleteGroupCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		if err := client.DeleteGroup(ctx.Context(), cmd.Group); err != nil {
			return err
		}
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// TABLES

type groupRow schema.Group

func (r groupRow) Header() []string {
	return []string{"Group", "Description", "Scopes", "Enabled"}
}

func (r groupRow) Cell(i int) string {
	switch i {
	case 0:
		return r.ID
	case 1:
		return types.Value(r.Description)
	case 2:
		return strings.Join(r.Scopes, ", ")
	case 3:
		return strconv.FormatBool(types.Value(r.Enabled))
	default:
		return ""
	}
}

func (r groupRow) Width(i int) int {
	return 0
}
