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

package certmanager

import (
	"fmt"
	"strings"
	"time"

	// Packages
	certclient "github.com/djthorpe/go-auth/pkg/httpclient/certmanager"
	schema "github.com/djthorpe/go-auth/schema/cert"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type certSubjectFlags struct {
	Org           string `name:"organization" help:"Subject organization name"`
	Unit          string `name:"organizational-unit" help:"Subject organizational unit"`
	Country       string `name:"country" help:"Subject country code"`
	City          string `name:"city" help:"Subject locality/city"`
	State         string `name:"state" help:"Subject state or province"`
	StreetAddress string `name:"street-address" help:"Subject street address"`
	PostalCode    string `name:"postal-code" help:"Subject postal code"`
}

type CACommands struct {
	CreateCA CreateCACommand `cmd:"" name:"ca-create" help:"Create certificate authority." group:"CERTIFICATE MANAGER"`
	RenewCA  RenewCACommand  `cmd:"" name:"ca-renew" help:"Renew certificate authority." group:"CERTIFICATE MANAGER"`
}

type CreateCACommand struct {
	Name    string        `arg:"" name:"name" help:"Certificate authority name"`
	Expiry  time.Duration `name:"expiry" help:"Certificate lifetime. Zero uses the server default."`
	Enabled bool          `name:"enabled" help:"Enable the created certificate authority." default:"true" negatable:""`
	Tags    []string      `name:"tag" help:"Tag to apply to the certificate authority. Repeat to set multiple tags."`
	certSubjectFlags
}

type RenewCACommand struct {
	Name      string        `arg:"" name:"name" help:"Certificate authority name"`
	Serial    string        `arg:"" optional:"" name:"serial" help:"Certificate authority serial number. Omit to use the latest certificate version."`
	Expiry    time.Duration `name:"expiry" help:"Certificate lifetime. Zero preserves the current lifetime, capped by the root validity."`
	Enable    bool          `name:"enable" help:"Enable the renewed certificate authority."`
	Disable   bool          `name:"disable" help:"Disable the renewed certificate authority."`
	Tags      []string      `name:"tag" help:"Replace certificate authority tags with the provided list. Repeat to set multiple tags."`
	ClearTags bool          `name:"clear-tags" help:"Clear all certificate authority tags on the renewed certificate."`
	certSubjectFlags
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *CreateCACommand) Run(ctx server.Cmd) error {
	return withUnauthenticatedClient(ctx, func(client *certclient.Client, endpoint string) error {
		ca, err := client.CreateCA(ctx.Context(), schema.CreateCertRequest{
			Name:    strings.TrimSpace(cmd.Name),
			Expiry:  cmd.Expiry,
			Subject: cmd.subject(),
			Enabled: types.Ptr(cmd.Enabled),
			Tags:    append([]string(nil), cmd.Tags...),
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(certmanagerOutput, ca)
		return err
	})
}

func (cmd *RenewCACommand) Run(ctx server.Cmd) error {
	req, err := renewRequest(cmd.Expiry, cmd.subject(), cmd.Enable, cmd.Disable, cmd.Tags, cmd.ClearTags)
	if err != nil {
		return err
	}

	return withUnauthenticatedClient(ctx, func(client *certclient.Client, endpoint string) error {
		ca, err := client.RenewCA(ctx.Context(), schema.CertKey{
			Name:   strings.TrimSpace(cmd.Name),
			Serial: strings.TrimSpace(cmd.Serial),
		}, req)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(certmanagerOutput, ca)
		return err
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (cmd *certSubjectFlags) subject() *schema.SubjectMeta {
	subject := schema.SubjectMeta{}
	if value := strings.TrimSpace(cmd.Org); value != "" {
		subject.Org = types.Ptr(value)
	}
	if value := strings.TrimSpace(cmd.Unit); value != "" {
		subject.Unit = types.Ptr(value)
	}
	if value := strings.TrimSpace(cmd.Country); value != "" {
		subject.Country = types.Ptr(value)
	}
	if value := strings.TrimSpace(cmd.City); value != "" {
		subject.City = types.Ptr(value)
	}
	if value := strings.TrimSpace(cmd.State); value != "" {
		subject.State = types.Ptr(value)
	}
	if value := strings.TrimSpace(cmd.StreetAddress); value != "" {
		subject.StreetAddress = types.Ptr(value)
	}
	if value := strings.TrimSpace(cmd.PostalCode); value != "" {
		subject.PostalCode = types.Ptr(value)
	}
	if subject == (schema.SubjectMeta{}) {
		return nil
	}
	return &subject
}
