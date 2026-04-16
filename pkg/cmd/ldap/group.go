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

package ldap

import (
	"fmt"

	// Packages
	ldap "github.com/mutablelogic/go-auth/pkg/httpclient/ldap"
	schema "github.com/mutablelogic/go-auth/schema/ldap"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type GroupListCommand schema.ObjectListRequest

type GroupGetCommand struct {
	CN string `arg:"" name:"cn" help:"Group common name"`
}

type GroupDeleteCommand struct {
	CN string `arg:"" name:"cn" help:"Group common name"`
}

type GroupCreateCommand struct {
	CN    string   `arg:"" name:"cn" help:"Group common name"`
	Attrs []string `arg:"" optional:"" name:"attrs" help:"Attributes as key=value1,value2"`
}

type GroupUpdateCommand struct {
	CN    string   `arg:"" name:"cn" help:"Group common name"`
	Attrs []string `arg:"" name:"attrs" help:"Attributes as key=value1,value2"`
}

type GroupAddUsersCommand struct {
	CN    string   `arg:"" name:"cn" help:"Group common name"`
	Users []string `arg:"" name:"users" help:"User names to add to the group"`
}

type GroupRemoveUsersCommand struct {
	CN    string   `arg:"" name:"cn" help:"Group common name"`
	Users []string `arg:"" name:"users" help:"User names to remove from the group"`
}

type GroupCommands struct {
	Group       GroupListCommand        `cmd:"" name:"groups" help:"List groups." group:"LDAP USERS & GROUPS"`
	Get         GroupGetCommand         `cmd:"" name:"group" help:"Get group." group:"LDAP USERS & GROUPS"`
	Delete      GroupDeleteCommand      `cmd:"" name:"group-delete" help:"Delete group." group:"LDAP USERS & GROUPS"`
	Create      GroupCreateCommand      `cmd:"" name:"group-create" help:"Create group." group:"LDAP USERS & GROUPS"`
	Update      GroupUpdateCommand      `cmd:"" name:"group-update" help:"Update group." group:"LDAP USERS & GROUPS"`
	AddUsers    GroupAddUsersCommand    `cmd:"" name:"group-add-users" help:"Add users to group." group:"LDAP USERS & GROUPS"`
	RemoveUsers GroupRemoveUsersCommand `cmd:"" name:"group-remove-users" help:"Remove users from group." group:"LDAP USERS & GROUPS"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *GroupListCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		groups, err := manager.ListGroups(ctx.Context(), schema.ObjectListRequest(*cmd))
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(groups)
		} else {
			fmt.Println(groups.LDIF())
		}
		return nil
	})
}

func (cmd *GroupGetCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		group, err := manager.GetGroup(ctx.Context(), cmd.CN)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(group)
		} else {
			fmt.Println(group.LDIF())
		}
		return nil
	})
}

func (cmd *GroupDeleteCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		group, err := manager.DeleteGroup(ctx.Context(), cmd.CN)
		if err != nil {
			return err
		}
		printDeletedObject(ctx, group)
		return nil
	})
}

func (cmd *GroupCreateCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		var req *schema.ObjectPutRequest
		if len(cmd.Attrs) > 0 {
			attrs, err := objectAttrs(cmd.Attrs)
			if err != nil {
				return err
			}
			req = &schema.ObjectPutRequest{Attrs: attrs}
		}
		group, err := manager.CreateGroup(ctx.Context(), cmd.CN, req)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(group)
		} else {
			fmt.Println(group.LDIF())
		}
		return nil
	})
}

func (cmd *GroupUpdateCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		attrs, err := objectAttrs(cmd.Attrs)
		if err != nil {
			return err
		}
		group, err := manager.UpdateGroup(ctx.Context(), cmd.CN, schema.ObjectPutRequest{Attrs: attrs})
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(group)
		} else {
			fmt.Println(group.LDIF())
		}
		return nil
	})
}

func (cmd *GroupAddUsersCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		group, err := manager.AddGroupUsers(ctx.Context(), cmd.CN, cmd.Users)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(group)
		} else {
			fmt.Println(group.LDIF())
		}
		return nil
	})
}

func (cmd *GroupRemoveUsersCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		group, err := manager.RemoveGroupUsers(ctx.Context(), cmd.CN, cmd.Users)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(group)
		} else {
			fmt.Println(group.LDIF())
		}
		return nil
	})
}
