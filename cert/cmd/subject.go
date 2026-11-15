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

package cert

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	httpclient "github.com/mutablelogic/go-auth/cert/httpclient"
	server "github.com/mutablelogic/go-server"
	tui "github.com/mutablelogic/go-server/pkg/tui"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// SubjectCommands list, create, update and delete the subjects which
// certificates are created with
type SubjectCommands struct {
	SubjectList   SubjectListCmd   `cmd:"" name:"subjects" help:"List subjects, with the number of certificates which use each." group:"CERTIFICATE"`
	SubjectCreate SubjectCreateCmd `cmd:"" name:"subject-create" help:"Create a subject, or show the identical one which is stored." group:"CERTIFICATE"`
	SubjectUpdate SubjectUpdateCmd `cmd:"" name:"subject-update" help:"Update a subject which no certificate uses. An empty value removes a field." group:"CERTIFICATE"`
	SubjectDelete SubjectDeleteCmd `cmd:"" name:"subject-delete" help:"Delete a subject which no certificate uses." group:"CERTIFICATE"`
}

type SubjectListCmd struct {
	Offset uint64  `name:"offset" help:"Offset within the list"`
	Limit  *uint64 `name:"limit" help:"Number of subjects to list"`
}

type SubjectCreateCmd struct {
	subjectFlags
}

type SubjectUpdateCmd struct {
	ID            uint64  `arg:"" name:"id" help:"Subject identifier"`
	Org           *string `name:"organization" help:"Subject organization name"`
	Unit          *string `name:"organizational-unit" help:"Subject organizational unit"`
	Country       *string `name:"country" help:"Subject country code"`
	City          *string `name:"city" help:"Subject locality or city"`
	State         *string `name:"state" help:"Subject state or province"`
	StreetAddress *string `name:"street-address" help:"Subject street address"`
	PostalCode    *string `name:"postal-code" help:"Subject postal code"`
}

type SubjectDeleteCmd struct {
	ID uint64 `arg:"" name:"id" help:"Subject identifier"`
}

// subjectRow is a row of the subjects table
type subjectRow cert.Subject

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *SubjectListCmd) Run(ctx server.Cmd) error {
	width, debug := ctx.IsTerm(), ctx.IsDebug()
	return withClient(ctx, "cert.SubjectListCmd", func(child context.Context, client *httpclient.Client) error {
		list, err := client.ListSubjects(child, cert.SubjectListRequest{OffsetLimit: cert.OffsetLimit{Offset: cmd.Offset, Limit: cmd.Limit}})
		if err != nil {
			return err
		}
		if debug {
			fmt.Println(list)
			return nil
		}
		rows := make([]subjectRow, 0, len(list.Body))
		for _, s := range list.Body {
			rows = append(rows, subjectRow(s))
		}
		if _, err := tui.TableFor[subjectRow](tui.SetWidth(width)).Write(os.Stdout, rows...); err != nil {
			return err
		}
		_, err = tui.TableSummary("subjects", uint(list.Count), uint(len(list.Body)), list.Offset, list.Limit).Write(os.Stdout)
		return err
	})
}

func (cmd *SubjectCreateCmd) Run(ctx server.Cmd) error {
	subject := cmd.subject()
	if subject == nil {
		return fmt.Errorf("a subject needs a field, such as --organization")
	}
	return withClient(ctx, "cert.SubjectCreateCmd", func(child context.Context, client *httpclient.Client) error {
		created, err := client.CreateSubject(child, *subject)
		return printSubject(ctx, "subject", created, err)
	})
}

func (cmd *SubjectUpdateCmd) Run(ctx server.Cmd) error {
	// A field which is set is changed, or removed when it's empty
	meta := cert.SubjectMeta{
		Org:           cmd.Org,
		Unit:          cmd.Unit,
		Country:       cmd.Country,
		City:          cmd.City,
		State:         cmd.State,
		StreetAddress: cmd.StreetAddress,
		PostalCode:    cmd.PostalCode,
	}
	if meta == (cert.SubjectMeta{}) {
		return fmt.Errorf("nothing to update: set a field, such as --organization, or an empty one to remove it")
	}
	return withClient(ctx, "cert.SubjectUpdateCmd", func(child context.Context, client *httpclient.Client) error {
		updated, err := client.UpdateSubject(child, cmd.ID, meta)
		return printSubject(ctx, "updated subject", updated, err)
	})
}

func (cmd *SubjectDeleteCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "cert.SubjectDeleteCmd", func(child context.Context, client *httpclient.Client) error {
		if err := client.DeleteSubject(child, cmd.ID); err != nil {
			return err
		}
		fmt.Println("deleted subject", cmd.ID)
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// printSubject prints what was done to a subject, with its identifier and
// name, or the subject with debugging
func printSubject(ctx server.Cmd, done string, s *cert.Subject, err error) error {
	if err != nil {
		return err
	}
	if ctx.IsDebug() {
		fmt.Println(s)
		return nil
	}
	fmt.Println(done, s.ID, types.Value(s.Subject))
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// TABLE

func (r subjectRow) Header() []string {
	return []string{"ID", "Subject", "Certificates", "Updated"}
}

func (r subjectRow) Width(int) int {
	return 0
}

func (r subjectRow) Cell(col int) tui.CellText {
	switch col {
	case 0:
		return fmt.Sprint(r.ID)
	case 1:
		return strings.TrimSpace(types.Value(r.Subject))
	case 2:
		return fmt.Sprint(r.Certs)
	case 3:
		if r.Ts.IsZero() {
			return ""
		}
		return r.Ts.Local().Format(time.DateTime)
	default:
		return ""
	}
}
