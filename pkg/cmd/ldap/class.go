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
	ldap "github.com/djthorpe/go-auth/pkg/httpclient/ldap"
	schema "github.com/djthorpe/go-auth/schema/ldap"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ClassListCommand schema.ObjectClassListRequest
type AttrListCommand schema.AttributeTypeListRequest

type ClassCommands struct {
	Class ClassListCommand `cmd:"" name:"class" help:"List Object Classes." group:"LDAP OBJECT SCHEMA"`
}

type AttrCommands struct {
	Attr AttrListCommand `cmd:"" name:"attr" help:"List Attribute Types." group:"LDAP OBJECT SCHEMA"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ClassListCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		classes, err := manager.ListObjectClasses(ctx.Context(), schema.ObjectClassListRequest(*cmd))
		if err != nil {
			return err
		}
		fmt.Println(classes)
		return nil
	})
}

func (cmd *AttrListCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		attrs, err := manager.ListAttributeTypes(ctx.Context(), schema.AttributeTypeListRequest(*cmd))
		if err != nil {
			return err
		}
		fmt.Println(attrs)
		return nil
	})
}
