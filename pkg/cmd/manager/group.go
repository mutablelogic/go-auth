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

type GroupCommands struct {
	Groups      ListGroupsCommand  `cmd:"" name:"groups" help:"Get Groups." group:"USER MANAGER"`
	Group       GetGroupCommand    `cmd:"" name:"group" help:"Get Group." group:"USER MANAGER"`
	CreateGroup CreateGroupCommand `cmd:"" name:"group-create" help:"Create Group." group:"USER MANAGER"`
	UpdateGroup UpdateGroupCommand `cmd:"" name:"group-update" help:"Update Group." group:"USER MANAGER"`
	DeleteGroup DeleteGroupCommand `cmd:"" name:"group-delete" help:"Delete Group." group:"USER MANAGER"`
}

type ListGroupsCommand struct {
	schema.GroupListRequest
}

type CreateGroupCommand struct {
	ID string `arg:"" name:"group" help:"Group identifier"`
	schema.GroupMeta
}

type GetGroupCommand struct {
	ID string `arg:"" name:"group" help:"Group identifier"`
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
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		groups, err := manager.ListGroups(ctx.Context(), cmd.GroupListRequest)
		if err != nil {
			return err
		}
		fmt.Println(groups)
		return nil
	})
}

func (cmd *CreateGroupCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		group, err := manager.CreateGroup(ctx.Context(), schema.GroupInsert{ID: cmd.ID, GroupMeta: cmd.GroupMeta})
		if err != nil {
			return err
		}
		fmt.Println(group)
		return nil
	})
}

func (cmd *GetGroupCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		group, err := manager.GetGroup(ctx.Context(), cmd.ID)
		if err != nil {
			return err
		}
		fmt.Println(group)
		return nil
	})
}

func (cmd *UpdateGroupCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		group, err := manager.UpdateGroup(ctx.Context(), cmd.ID, cmd.GroupMeta)
		if err != nil {
			return err
		}
		fmt.Println(group)
		return nil
	})
}

func (cmd *DeleteGroupCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		if err := manager.DeleteGroup(ctx.Context(), cmd.ID); err != nil {
			return err
		}
		fmt.Println(cmd.ID)
		return nil
	})
}
