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

type UserListCommand schema.ObjectListRequest

type UserGetCommand struct {
	CN string `arg:"" name:"cn" help:"User name"`
}

type UserDeleteCommand struct {
	CN string `arg:"" name:"cn" help:"User name"`
}

type UserCreateCommand struct {
	CN          string   `arg:"" name:"cn" help:"User name"`
	Attrs       []string `arg:"" optional:"" name:"attrs" help:"Attributes as key=value1,value2"`
	AllocateGID bool     `name:"allocate-gid" help:"Set gidNumber to uidNumber when gidNumber is omitted"`
}

type UserUpdateCommand struct {
	CN    string   `arg:"" name:"cn" help:"User name"`
	Attrs []string `arg:"" name:"attrs" help:"Attributes as key=value1,value2"`
}

type UserCommands struct {
	Users  UserListCommand   `cmd:"" name:"users" help:"List users." group:"LDAP USERS & GROUPS"`
	User   UserGetCommand    `cmd:"" name:"user" help:"Get user." group:"LDAP USERS & GROUPS"`
	Delete UserDeleteCommand `cmd:"" name:"user-delete" help:"Delete user." group:"LDAP USERS & GROUPS"`
	Create UserCreateCommand `cmd:"" name:"user-create" help:"Create user." group:"LDAP USERS & GROUPS"`
	Update UserUpdateCommand `cmd:"" name:"user-update" help:"Update user." group:"LDAP USERS & GROUPS"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *UserListCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		users, err := manager.ListUsers(ctx.Context(), schema.ObjectListRequest(*cmd))
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(users)
		} else {
			fmt.Println(users.LDIF())
		}
		return nil
	})
}

func (cmd *UserGetCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		user, err := manager.GetUser(ctx.Context(), cmd.CN)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(user)
		} else {
			fmt.Println(user.LDIF())
		}
		return nil
	})
}

func (cmd *UserDeleteCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		user, err := manager.DeleteUser(ctx.Context(), cmd.CN)
		if err != nil {
			return err
		}
		printDeletedObject(ctx, user)
		return nil
	})
}

func (cmd *UserCreateCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		var req *schema.ObjectPutRequest
		if len(cmd.Attrs) > 0 {
			attrs, err := objectAttrs(cmd.Attrs)
			if err != nil {
				return err
			}
			req = &schema.ObjectPutRequest{Attrs: attrs}
		}
		user, err := manager.CreateUser(ctx.Context(), cmd.CN, req, cmd.AllocateGID)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(user)
		} else {
			fmt.Println(user.LDIF())
		}
		return nil
	})
}

func (cmd *UserUpdateCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		attrs, err := objectAttrs(cmd.Attrs)
		if err != nil {
			return err
		}
		user, err := manager.UpdateUser(ctx.Context(), cmd.CN, schema.ObjectPutRequest{Attrs: attrs})
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(user)
		} else {
			fmt.Println(user.LDIF())
		}
		return nil
	})
}
