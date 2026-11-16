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

// UserCommands list, get, create, update and delete users, by name
type UserCommands struct {
	UserList   UserListCmd   `cmd:"" name:"ldap-users" help:"List the users, or a group's members, as LDIF." group:"LDAP"`
	UserGet    UserGetCmd    `cmd:"" name:"ldap-user" help:"Get a user, by name, as LDIF." group:"LDAP"`
	UserCreate UserCreateCmd `cmd:"" name:"ldap-user-create" help:"Create a user, with attributes as name=value. A userPassword is set as its password." group:"LDAP"`
	UserUpdate UserUpdateCmd `cmd:"" name:"ldap-user-update" help:"Update a user, with attributes as name=value, which replace its values, or name=, which deletes them. Changing its name renames it." group:"LDAP"`
	UserDelete UserDeleteCmd `cmd:"" name:"ldap-user-delete" help:"Delete a user." group:"LDAP"`
}

type UserListCmd struct {
	Group  string   `name:"group" help:"Only the group's members"`
	Filter string   `name:"filter" help:"LDAP filter, such as (cn=a*)"`
	Attr   []string `name:"attr" help:"Attribute to return. Repeat for more than one."`
	Offset uint64   `name:"offset" help:"Offset within the list"`
	Limit  *uint64  `name:"limit" help:"Number of users to list"`
}

type UserGetCmd struct {
	Name string `arg:"" name:"name" help:"User name, which is its uid, or cn in Active Directory"`
}

type UserCreateCmd struct {
	Name        string   `arg:"" name:"name" help:"User name, which is its uid, or cn in Active Directory"`
	Attrs       []string `arg:"" optional:"" name:"attrs" help:"Attributes as name=value, repeated for more values"`
	AllocateGID bool     `name:"allocate-gid" help:"Set the gidNumber to the uidNumber, for a posixAccount"`
}

type UserUpdateCmd struct {
	Name  string   `arg:"" name:"name" help:"User name"`
	Attrs []string `arg:"" name:"attrs" help:"Attributes as name=value, repeated for more values, or name= to delete them"`
}

type UserDeleteCmd struct {
	Name string `arg:"" name:"name" help:"User name"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *UserListCmd) Run(ctx server.Cmd) error {
	req := schema.UserListRequest{ListRequest: listRequest(cmd.Filter, cmd.Attr, cmd.Offset, cmd.Limit)}
	if cmd.Group != "" {
		req.Group = types.Ptr(cmd.Group)
	}
	return withClient(ctx, "ldap.UserListCmd", func(child context.Context, client *httpclient.Client) error {
		list, err := client.ListUsers(child, req)
		if err != nil {
			return err
		}
		printObject(ctx, "", list, list.LDIF())
		return nil
	})
}

func (cmd *UserGetCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "ldap.UserGetCmd", func(child context.Context, client *httpclient.Client) error {
		user, err := client.GetUser(child, cmd.Name)
		if err != nil {
			return err
		}
		printObject(ctx, "", user, user.LDIF())
		return nil
	})
}

func (cmd *UserCreateCmd) Run(ctx server.Cmd) error {
	attrs, err := parseAttrs(cmd.Attrs)
	if err != nil {
		return err
	}
	return withClient(ctx, "ldap.UserCreateCmd", func(child context.Context, client *httpclient.Client) error {
		user, err := client.CreateUser(child, cmd.Name, attrs, cmd.AllocateGID)
		if err != nil {
			return err
		}
		printObject(ctx, "created", user, user.LDIF())
		return nil
	})
}

func (cmd *UserUpdateCmd) Run(ctx server.Cmd) error {
	attrs, err := parseAttrs(cmd.Attrs)
	if err != nil {
		return err
	}
	return withClient(ctx, "ldap.UserUpdateCmd", func(child context.Context, client *httpclient.Client) error {
		user, err := client.UpdateUser(child, cmd.Name, attrs)
		if err != nil {
			return err
		}
		printObject(ctx, "updated", user, user.LDIF())
		return nil
	})
}

func (cmd *UserDeleteCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "ldap.UserDeleteCmd", func(child context.Context, client *httpclient.Client) error {
		user, err := client.DeleteUser(child, cmd.Name)
		if err != nil {
			return err
		}
		printObject(ctx, "deleted", user, user.LDIF())
		return nil
	})
}
