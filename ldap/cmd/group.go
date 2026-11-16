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
	"context"

	// Packages
	httpclient "github.com/mutablelogic/go-auth/ldap/httpclient"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// GroupCommands list, get, create, update and delete groups, by name, and
// add and remove their members
type GroupCommands struct {
	GroupList   GroupListCmd   `cmd:"" name:"ldap-groups" help:"List the groups, or a user's, as LDIF." group:"LDAP"`
	GroupGet    GroupGetCmd    `cmd:"" name:"ldap-group" help:"Get a group, by name, as LDIF." group:"LDAP"`
	GroupCreate GroupCreateCmd `cmd:"" name:"ldap-group-create" help:"Create a group, with attributes as name=value." group:"LDAP"`
	GroupUpdate GroupUpdateCmd `cmd:"" name:"ldap-group-update" help:"Update a group, with attributes as name=value, which replace its values, or name=, which deletes them. Changing its cn renames it." group:"LDAP"`
	GroupDelete GroupDeleteCmd `cmd:"" name:"ldap-group-delete" help:"Delete a group." group:"LDAP"`
	GroupAdd    GroupAddCmd    `cmd:"" name:"ldap-group-add" help:"Add users to a group." group:"LDAP"`
	GroupRemove GroupRemoveCmd `cmd:"" name:"ldap-group-remove" help:"Remove users from a group." group:"LDAP"`
}

type GroupListCmd struct {
	User   string   `name:"user" help:"Only the groups the user is a member of"`
	Filter string   `name:"filter" help:"LDAP filter, such as (cn=a*)"`
	Attr   []string `name:"attr" help:"Attribute to return. Repeat for more than one."`
	Offset uint64   `name:"offset" help:"Offset within the list"`
	Limit  *uint64  `name:"limit" help:"Number of groups to list"`
}

type GroupGetCmd struct {
	Name string `arg:"" name:"name" help:"Group name, which is its cn"`
}

type GroupCreateCmd struct {
	Name  string   `arg:"" name:"name" help:"Group name, which is its cn"`
	Attrs []string `arg:"" optional:"" name:"attrs" help:"Attributes as name=value, repeated for more values"`
}

type GroupUpdateCmd struct {
	Name  string   `arg:"" name:"name" help:"Group name"`
	Attrs []string `arg:"" name:"attrs" help:"Attributes as name=value, repeated for more values, or name= to delete them"`
}

type GroupDeleteCmd struct {
	Name string `arg:"" name:"name" help:"Group name"`
}

type GroupAddCmd struct {
	Name  string   `arg:"" name:"name" help:"Group name"`
	Users []string `arg:"" name:"users" help:"Users to add, by name"`
}

type GroupRemoveCmd struct {
	Name  string   `arg:"" name:"name" help:"Group name"`
	Users []string `arg:"" name:"users" help:"Users to remove, by name"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *GroupListCmd) Run(ctx server.Cmd) error {
	req := schema.GroupListRequest{ListRequest: listRequest(cmd.Filter, cmd.Attr, cmd.Offset, cmd.Limit)}
	if cmd.User != "" {
		req.User = types.Ptr(cmd.User)
	}
	return withClient(ctx, "ldap.GroupListCmd", func(child context.Context, client *httpclient.Client) error {
		list, err := client.ListGroups(child, req)
		if err != nil {
			return err
		}
		printObject(ctx, "", list, list.LDIF())
		return nil
	})
}

func (cmd *GroupGetCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "ldap.GroupGetCmd", func(child context.Context, client *httpclient.Client) error {
		group, err := client.GetGroup(child, cmd.Name)
		if err != nil {
			return err
		}
		printObject(ctx, "", group, group.LDIF())
		return nil
	})
}

func (cmd *GroupCreateCmd) Run(ctx server.Cmd) error {
	attrs, err := parseAttrs(cmd.Attrs)
	if err != nil {
		return err
	}
	return withClient(ctx, "ldap.GroupCreateCmd", func(child context.Context, client *httpclient.Client) error {
		group, err := client.CreateGroup(child, cmd.Name, attrs)
		if err != nil {
			return err
		}
		printObject(ctx, "created", group, group.LDIF())
		return nil
	})
}

func (cmd *GroupUpdateCmd) Run(ctx server.Cmd) error {
	attrs, err := parseAttrs(cmd.Attrs)
	if err != nil {
		return err
	}
	return withClient(ctx, "ldap.GroupUpdateCmd", func(child context.Context, client *httpclient.Client) error {
		group, err := client.UpdateGroup(child, cmd.Name, attrs)
		if err != nil {
			return err
		}
		printObject(ctx, "updated", group, group.LDIF())
		return nil
	})
}

func (cmd *GroupDeleteCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "ldap.GroupDeleteCmd", func(child context.Context, client *httpclient.Client) error {
		group, err := client.DeleteGroup(child, cmd.Name)
		if err != nil {
			return err
		}
		printObject(ctx, "deleted", group, group.LDIF())
		return nil
	})
}

func (cmd *GroupAddCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "ldap.GroupAddCmd", func(child context.Context, client *httpclient.Client) error {
		group, err := client.AddGroupUsers(child, cmd.Name, cmd.Users...)
		if err != nil {
			return err
		}
		printObject(ctx, "added users to", group, group.LDIF())
		return nil
	})
}

func (cmd *GroupRemoveCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "ldap.GroupRemoveCmd", func(child context.Context, client *httpclient.Client) error {
		group, err := client.RemoveGroupUsers(child, cmd.Name, cmd.Users...)
		if err != nil {
			return err
		}
		printObject(ctx, "removed users from", group, group.LDIF())
		return nil
	})
}
