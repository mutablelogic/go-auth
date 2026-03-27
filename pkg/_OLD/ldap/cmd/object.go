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

package cmd

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	// Packages
	server "github.com/mutablelogic/go-server"
	client "github.com/mutablelogic/go-server/pkg/ldap/client"
	schema "github.com/mutablelogic/go-server/pkg/ldap/schema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ObjectCommands struct {
	Objects      ObjectListCommand   `cmd:"" group:"LDAP" help:"List queues"`
	Object       ObjectGetCommand    `cmd:"" group:"LDAP" help:"Get object by DN"`
	CreateObject ObjectCreateCommand `cmd:"" group:"LDAP" help:"Create object"`
	UpdateObject ObjectUpdateCommand `cmd:"" group:"LDAP" help:"Update object attributes by DN"`
	DeleteObject ObjectDeleteCommand `cmd:"" group:"LDAP" help:"Delete object by DN"`
}

type ObjectListCommand struct {
	schema.ObjectListRequest
}

type ObjectGetCommand struct {
	DN string `arg:"" help:"Distingushed Name"`
}

type ObjectCreateCommand struct {
	ObjectGetCommand
	Attr []string `arg:"" help:"attribute=value,value,..."`
}

type ObjectUpdateCommand struct {
	ObjectCreateCommand
}

type ObjectDeleteCommand struct {
	ObjectGetCommand
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (cmd ObjectListCommand) Run(ctx server.Cmd) error {
	return run(ctx, func(ctx context.Context, provider *client.Client) error {
		objects, err := provider.ListObjects(ctx, client.WithFilter(cmd.Filter), client.WithAttr(cmd.Attr...), client.WithOffsetLimit(cmd.Offset, cmd.Limit))
		if err != nil {
			return err
		}

		// Print objects
		fmt.Println(objects)
		return nil
	})
}

func (cmd ObjectCreateCommand) Run(ctx server.Cmd) error {
	return run(ctx, func(ctx context.Context, provider *client.Client) error {
		// Decode attributes
		attrs := url.Values{}
		for _, attr := range cmd.Attr {
			parts := strings.SplitN(attr, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid attribute: %s", attr)
			}
			name := parts[0]
			if values := strings.Split(parts[1], ","); len(values) > 0 {
				attrs[name] = values
			}
		}

		// Create object
		object, err := provider.CreateObject(ctx, schema.Object{
			DN:     cmd.DN,
			Values: attrs,
		})
		if err != nil {
			return err
		}

		// Print object
		fmt.Println(object)
		return nil
	})
}

func (cmd ObjectUpdateCommand) Run(ctx server.Cmd) error {
	return run(ctx, func(ctx context.Context, provider *client.Client) error {
		// Decode attributes
		attrs := url.Values{}
		for _, attr := range cmd.Attr {
			parts := strings.SplitN(attr, "=", 2)
			name := parts[0]
			if len(parts) == 1 {
				attrs[name] = []string{}
			} else {
				attrs[name] = strings.Split(parts[1], ",")
			}
		}

		// Update object
		object, err := provider.UpdateObject(ctx, schema.Object{
			DN:     cmd.DN,
			Values: attrs,
		})
		if err != nil {
			return err
		}

		// Print object
		fmt.Println(object)
		return nil
	})
}

func (cmd ObjectGetCommand) Run(ctx server.Cmd) error {
	return run(ctx, func(ctx context.Context, provider *client.Client) error {
		object, err := provider.GetObject(ctx, cmd.DN)
		if err != nil {
			return err
		}

		// Print object
		fmt.Println(object)
		return nil
	})
}

func (cmd ObjectDeleteCommand) Run(ctx server.Cmd) error {
	return run(ctx, func(ctx context.Context, provider *client.Client) error {
		return provider.DeleteObject(ctx, cmd.DN)
	})
}
