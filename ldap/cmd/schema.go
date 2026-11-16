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
	"fmt"
	"os"
	"sort"
	"strings"

	// Packages
	httpclient "github.com/mutablelogic/go-auth/ldap/httpclient"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	server "github.com/mutablelogic/go-server"
	tui "github.com/mutablelogic/go-server/pkg/tui"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// SchemaCommands list the directory's object classes and attribute types
type SchemaCommands struct {
	ClassList ClassListCmd `cmd:"" name:"ldap-classes" help:"List the directory's object classes, by name." group:"LDAP"`
	AttrList  AttrListCmd  `cmd:"" name:"ldap-attrs" help:"List the directory's attribute types, by name." group:"LDAP"`
}

type ClassListCmd struct {
	Filter string   `arg:"" optional:"" name:"filter" help:"Name or OID"`
	Kind   string   `name:"kind" enum:",ABSTRACT,STRUCTURAL,AUXILIARY" default:"" help:"ABSTRACT, STRUCTURAL or AUXILIARY"`
	Must   []string `name:"must" help:"Only classes which need the attribute. Repeat for more than one."`
	May    []string `name:"may" help:"Only classes which can have the attribute. Repeat for more than one."`
	Offset uint64   `name:"offset" help:"Offset within the list"`
	Limit  *uint64  `name:"limit" help:"Number of classes to list"`
}

type AttrListCmd struct {
	Filter string  `arg:"" optional:"" name:"filter" help:"Name or OID"`
	Usage  string  `name:"usage" enum:",userApplications,directoryOperation,distributedOperation,dSAOperation" default:"" help:"userApplications, directoryOperation, distributedOperation or dSAOperation"`
	Offset uint64  `name:"offset" help:"Offset within the list"`
	Limit  *uint64 `name:"limit" help:"Number of attribute types to list"`
}

// classRow and attrRow are rows of the tables
type classRow schema.ObjectClass
type attrRow schema.AttributeType

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ClassListCmd) Run(ctx server.Cmd) error {
	req := schema.ObjectClassListRequest{OffsetLimit: schema.OffsetLimit{Offset: cmd.Offset, Limit: cmd.Limit}, Must: cmd.Must, May: cmd.May}
	if cmd.Filter != "" {
		req.Filter = types.Ptr(cmd.Filter)
	}
	if cmd.Kind != "" {
		req.Kind = types.Ptr(schema.ObjectClassKind(cmd.Kind))
	}
	width, debug := ctx.IsTerm(), ctx.IsDebug()
	return withClient(ctx, "ldap.ClassListCmd", func(child context.Context, client *httpclient.Client) error {
		list, err := client.ListObjectClasses(child, req)
		if err != nil {
			return err
		} else if debug {
			fmt.Println(list)
			return nil
		}
		rows := make([]classRow, 0, len(list.Body))
		for _, class := range list.Body {
			rows = append(rows, classRow(*class))
		}
		if _, err := tui.TableFor[classRow](tui.SetWidth(width)).Write(os.Stdout, rows...); err != nil {
			return err
		}
		_, err = tui.TableSummary("classes", uint(list.Count), uint(len(list.Body)), req.Offset, req.Limit).Write(os.Stdout)
		return err
	})
}

func (cmd *AttrListCmd) Run(ctx server.Cmd) error {
	req := schema.AttributeTypeListRequest{OffsetLimit: schema.OffsetLimit{Offset: cmd.Offset, Limit: cmd.Limit}}
	if cmd.Filter != "" {
		req.Filter = types.Ptr(cmd.Filter)
	}
	if cmd.Usage != "" {
		req.Usage = types.Ptr(schema.AttributeUsage(cmd.Usage))
	}
	width, debug := ctx.IsTerm(), ctx.IsDebug()
	return withClient(ctx, "ldap.AttrListCmd", func(child context.Context, client *httpclient.Client) error {
		list, err := client.ListAttributeTypes(child, req)
		if err != nil {
			return err
		} else if debug {
			fmt.Println(list)
			return nil
		}
		rows := make([]attrRow, 0, len(list.Body))
		for _, attr := range list.Body {
			rows = append(rows, attrRow(*attr))
		}
		if _, err := tui.TableFor[attrRow](tui.SetWidth(width)).Write(os.Stdout, rows...); err != nil {
			return err
		}
		_, err = tui.TableSummary("attribute types", uint(list.Count), uint(len(list.Body)), req.Offset, req.Limit).Write(os.Stdout)
		return err
	})
}

///////////////////////////////////////////////////////////////////////////////
// TABLES

func (r classRow) Header() []string {
	return []string{"Name", "OID", "Kind", "Superior", "Must", "May"}
}

func (r classRow) Width(int) int {
	return 0
}

func (r classRow) Cell(col int) tui.CellText {
	class := schema.ObjectClass(r)
	switch col {
	case 0:
		return class.Identifier()
	case 1:
		return class.NumericOID
	case 2:
		return string(class.ClassKind)
	case 3:
		return strings.Join(class.SuperClasses, ", ")
	case 4:
		return strings.Join(class.Must, ", ")
	case 5:
		return strings.Join(class.May, ", ")
	default:
		return ""
	}
}

func (r attrRow) Header() []string {
	return []string{"Name", "OID", "Superior", "Usage", "Flags", "Description"}
}

func (r attrRow) Width(int) int {
	return 0
}

func (r attrRow) Cell(col int) tui.CellText {
	attr := schema.AttributeType(r)
	switch col {
	case 0:
		return attr.Identifier()
	case 1:
		return attr.NumericOID
	case 2:
		return attr.SuperType
	case 3:
		return string(attr.Usage)
	case 4:
		var flags []string
		for flag, set := range map[string]bool{"single": attr.SingleValue, "obsolete": attr.Obsolete, "collective": attr.Collective, "read-only": attr.NoUserModification} {
			if set {
				flags = append(flags, flag)
			}
		}
		sort.Strings(flags)
		return strings.Join(flags, ", ")
	case 5:
		return attr.Description
	default:
		return ""
	}
}
