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
	auth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/ldap/httpclient"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ObjectCommands list, get, create, update and delete entries, by DN, bind
// as them, and change their passwords
type ObjectCommands struct {
	ObjectList     ObjectListCmd     `cmd:"" name:"ldap-objects" help:"List the entries under the base DN, or a prefix, as LDIF." group:"LDAP"`
	ObjectGet      ObjectGetCmd      `cmd:"" name:"ldap-object" help:"Get an entry, by DN, as LDIF." group:"LDAP"`
	ObjectCreate   ObjectCreateCmd   `cmd:"" name:"ldap-object-create" help:"Create an entry, with attributes as name=value, which need an objectClass." group:"LDAP"`
	ObjectUpdate   ObjectUpdateCmd   `cmd:"" name:"ldap-object-update" help:"Update an entry, with attributes as name=value, which replace its values, or name=, which deletes them. Changing its RDN renames it." group:"LDAP"`
	ObjectDelete   ObjectDeleteCmd   `cmd:"" name:"ldap-object-delete" help:"Delete an entry, which has no children." group:"LDAP"`
	ObjectBind     ObjectBindCmd     `cmd:"" name:"ldap-object-bind" help:"Check an entry's password, which is prompted for, or read from the input." group:"LDAP"`
	ObjectPassword ObjectPasswordCmd `cmd:"" name:"ldap-object-password" help:"Change an entry's password, or reset it, which is prompted for, or read from the input, or generated." group:"LDAP"`
}

type ObjectListCmd struct {
	Prefix   string   `name:"prefix" help:"DN of the subtree to list, relative to the base DN"`
	Children bool     `name:"children" help:"Only the entries directly under the prefix, or the base DN"`
	Filter   string   `name:"filter" help:"LDAP filter, such as (cn=a*)"`
	Attr     []string `name:"attr" help:"Attribute to return. Repeat for more than one."`
	Offset   uint64   `name:"offset" help:"Offset within the list"`
	Limit    *uint64  `name:"limit" help:"Number of entries to list"`
}

type ObjectGetCmd struct {
	DN string `arg:"" name:"dn" help:"DN, relative to the base DN, or under it"`
}

type ObjectCreateCmd struct {
	DN    string   `arg:"" name:"dn" help:"DN, relative to the base DN, or under it"`
	Attrs []string `arg:"" name:"attrs" help:"Attributes as name=value, repeated for more values"`
}

type ObjectUpdateCmd struct {
	DN    string   `arg:"" name:"dn" help:"DN, relative to the base DN, or under it"`
	Attrs []string `arg:"" name:"attrs" help:"Attributes as name=value, repeated for more values, or name= to delete them"`
}

type ObjectDeleteCmd struct {
	DN string `arg:"" name:"dn" help:"DN, relative to the base DN, or under it"`
}

type ObjectBindCmd struct {
	DN string `arg:"" name:"dn" help:"DN, relative to the base DN, or under it"`
}

type ObjectPasswordCmd struct {
	DN       string `arg:"" name:"dn" help:"DN, relative to the base DN, or under it"`
	Old      bool   `name:"old" help:"Change the password with the old one, which is checked, rather than resetting it"`
	Generate bool   `name:"generate" help:"Generate the new password, which is printed"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ObjectListCmd) Run(ctx server.Cmd) error {
	req := schema.ObjectListRequest{ListRequest: listRequest(cmd.Filter, cmd.Attr, cmd.Offset, cmd.Limit), Children: cmd.Children}
	if cmd.Prefix != "" {
		req.Prefix = types.Ptr(cmd.Prefix)
	}
	return withClient(ctx, "ldap.ObjectListCmd", func(child context.Context, client *httpclient.Client) error {
		list, err := client.ListObjects(child, req)
		if err != nil {
			return err
		}
		printObject(ctx, "", list, list.LDIF())
		return nil
	})
}

func (cmd *ObjectGetCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "ldap.ObjectGetCmd", func(child context.Context, client *httpclient.Client) error {
		object, err := client.GetObject(child, cmd.DN)
		if err != nil {
			return err
		}
		printObject(ctx, "", object, object.LDIF())
		return nil
	})
}

func (cmd *ObjectCreateCmd) Run(ctx server.Cmd) error {
	attrs, err := parseAttrs(cmd.Attrs)
	if err != nil {
		return err
	}
	return withClient(ctx, "ldap.ObjectCreateCmd", func(child context.Context, client *httpclient.Client) error {
		object, err := client.CreateObject(child, cmd.DN, attrs)
		if err != nil {
			return err
		}
		printObject(ctx, "created", object, object.LDIF())
		return nil
	})
}

func (cmd *ObjectUpdateCmd) Run(ctx server.Cmd) error {
	attrs, err := parseAttrs(cmd.Attrs)
	if err != nil {
		return err
	}
	return withClient(ctx, "ldap.ObjectUpdateCmd", func(child context.Context, client *httpclient.Client) error {
		object, err := client.UpdateObject(child, cmd.DN, attrs)
		if err != nil {
			return err
		}
		printObject(ctx, "updated", object, object.LDIF())
		return nil
	})
}

func (cmd *ObjectDeleteCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "ldap.ObjectDeleteCmd", func(child context.Context, client *httpclient.Client) error {
		object, err := client.DeleteObject(child, cmd.DN)
		if err != nil {
			return err
		}
		printObject(ctx, "deleted", object, object.LDIF())
		return nil
	})
}

func (cmd *ObjectBindCmd) Run(ctx server.Cmd) error {
	password, err := readPassword("Password: ")
	if err != nil {
		return err
	} else if password == "" {
		return auth.ErrBadParameter.With("a password is needed")
	}
	return withClient(ctx, "ldap.ObjectBindCmd", func(child context.Context, client *httpclient.Client) error {
		object, err := client.BindObject(child, cmd.DN, password)
		if err != nil {
			return err
		}
		printObject(ctx, "bound", object, object.LDIF())
		return nil
	})
}

func (cmd *ObjectPasswordCmd) Run(ctx server.Cmd) error {
	var req schema.ObjectPasswordRequest
	if cmd.Old {
		old, err := readPassword("Old password: ")
		if err != nil {
			return err
		}
		req.Old = old
	}
	if !cmd.Generate {
		password, err := readPassword("New password: ")
		if err != nil {
			return err
		} else if password == "" {
			return auth.ErrBadParameter.With("a new password is needed, or set --generate")
		}
		confirm, err := readPassword("Confirm the new password: ")
		if err != nil {
			return err
		} else if confirm != password {
			return auth.ErrBadParameter.With("the passwords aren't the same")
		}
		req.New = types.Ptr(password)
	}
	return withClient(ctx, "ldap.ObjectPasswordCmd", func(child context.Context, client *httpclient.Client) error {
		response, err := client.ChangeObjectPassword(child, cmd.DN, req)
		if err != nil {
			return err
		}
		printObject(ctx, "changed the password of", response, response.LDIF())
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// listRequest is the paging, filter and attributes of a list
func listRequest(filter string, attrs []string, offset uint64, limit *uint64) schema.ListRequest {
	req := schema.ListRequest{OffsetLimit: schema.OffsetLimit{Offset: offset, Limit: limit}, Attr: attrs}
	if filter != "" {
		req.Filter = types.Ptr(filter)
	}
	return req
}
