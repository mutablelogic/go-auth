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
	term "golang.org/x/term"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// CertCommands create, renew, list, get and update certificate authorities
// and certificates
type CertCommands struct {
	CACreate   CACreateCmd   `cmd:"" name:"ca-create" help:"Create a certificate authority, signed by the root." group:"CERTIFICATE"`
	CARenew    CARenewCmd    `cmd:"" name:"ca-renew" help:"Renew a certificate authority. The current version stays enabled." group:"CERTIFICATE"`
	CertList   CertListCmd   `cmd:"" name:"certs" help:"List certificates." group:"CERTIFICATE"`
	CertGet    CertGetCmd    `cmd:"" name:"cert" help:"Get a certificate as PEM, with its chain or private key. Prints a private key only to a pipe or file, unless --show is set." group:"CERTIFICATE"`
	CertCreate CertCreateCmd `cmd:"" name:"cert-create" help:"Create a certificate, signed by a certificate authority." group:"CERTIFICATE"`
	CertRenew  CertRenewCmd  `cmd:"" name:"cert-renew" help:"Renew a certificate, which disables the current version." group:"CERTIFICATE"`
	CertUpdate CertUpdateCmd `cmd:"" name:"cert-update" help:"Enable or disable a certificate, or change its tags." group:"CERTIFICATE"`
}

type CACreateCmd struct {
	Name   string        `arg:"" name:"name" help:"Certificate authority name"`
	Expiry time.Duration `name:"expiry" help:"Lifetime, which is five years when it's not set, capped at the root's expiry"`
	Tags   []string      `name:"tag" help:"Tag. Repeat for more than one."`
	subjectFlags
}

type CARenewCmd struct {
	Name   string        `arg:"" name:"name" help:"Certificate authority name"`
	Serial string        `arg:"" optional:"" name:"serial" help:"Serial number, which is the latest version when it's not set"`
	Expiry time.Duration `name:"expiry" help:"Lifetime, which is the current one when it's not set, capped at the root's expiry"`
	subjectFlags
}

type CertListCmd struct {
	CA      *bool    `name:"ca" negatable:"" help:"Only certificate authorities, or with --no-ca, only leaf certificates"`
	Enabled *bool    `name:"enabled" negatable:"" help:"Only enabled certificates, or with --no-enabled, only disabled ones"`
	Valid   *bool    `name:"valid" negatable:"" help:"Only certificates within their validity period, or with --no-valid, only those outside it"`
	Tags    []string `name:"tag" help:"Only certificates with the tag. Repeat to require more than one."`
	Offset  uint64   `name:"offset" help:"Offset within the list"`
	Limit   *uint64  `name:"limit" help:"Number of certificates to list"`
}

type CertGetCmd struct {
	Name     string `arg:"" name:"name" help:"Certificate name"`
	Serial   string `arg:"" optional:"" name:"serial" help:"Serial number, which is the latest version when it's not set"`
	Chain    bool   `name:"chain" help:"Include the issuer chain, up to the root"`
	Key      bool   `name:"key" help:"Include the private key, of a leaf certificate"`
	Show     bool   `name:"show" help:"Print a private key when the output is a terminal, rather than a pipe or file"`
	Comments bool   `name:"comments" default:"true" negatable:"" help:"Write the certificate's details as comments before each PEM block"`
}

type CertCreateCmd struct {
	Name     string        `arg:"" name:"name" help:"Certificate name"`
	CA       string        `arg:"" name:"ca" help:"Certificate authority name"`
	CASerial string        `arg:"" optional:"" name:"serial" help:"Certificate authority serial number, which is its latest version when it's not set"`
	Expiry   time.Duration `name:"expiry" help:"Lifetime, which is 90 days when it's not set, capped at the certificate authority's expiry"`
	SAN      []string      `name:"san" help:"Subject alternative name: a DNS name, a wildcard such as *.example.com, or an IP address. Repeat for more than one."`
	Tags     []string      `name:"tag" help:"Tag. Repeat for more than one."`
	subjectFlags
}

type CertRenewCmd struct {
	Name   string        `arg:"" name:"name" help:"Certificate name"`
	Serial string        `arg:"" optional:"" name:"serial" help:"Serial number, which is the latest version when it's not set"`
	Expiry time.Duration `name:"expiry" help:"Lifetime, which is the current one when it's not set, capped at the certificate authority's expiry"`
	subjectFlags
}

type CertUpdateCmd struct {
	Name      string   `arg:"" name:"name" help:"Certificate name"`
	Serial    string   `arg:"" optional:"" name:"serial" help:"Serial number, which is the latest version when it's not set"`
	Enabled   *bool    `name:"enabled" negatable:"" help:"Enable the certificate, or with --no-enabled, disable it, and the certificates it signed"`
	Tags      []string `name:"tag" help:"Replace the tags. Repeat for more than one."`
	ClearTags bool     `name:"clear-tags" help:"Remove the tags"`
}

// certRow is a row of the certificates table
type certRow cert.Certificate

///////////////////////////////////////////////////////////////////////////////
// COMMANDS - CERTIFICATE AUTHORITIES

func (cmd *CACreateCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "cert.CACreateCmd", func(child context.Context, client *httpclient.Client) error {
		ca, err := client.CreateCA(child, cert.CreateCertRequest{
			Name:    cmd.Name,
			Expiry:  cmd.Expiry,
			Subject: cmd.subject(),
			Tags:    cmd.Tags,
		})
		return printCert(ctx, "created certificate authority", ca, err)
	})
}

func (cmd *CARenewCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "cert.CARenewCmd", func(child context.Context, client *httpclient.Client) error {
		ca, err := client.RenewCA(child, key(cmd.Name, cmd.Serial), cert.RenewCertRequest{Expiry: cmd.Expiry, Subject: cmd.subject()})
		return printCert(ctx, "renewed certificate authority", ca, err)
	})
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS - CERTIFICATES

func (cmd *CertListCmd) Run(ctx server.Cmd) error {
	width, debug := ctx.IsTerm(), ctx.IsDebug()
	return withClient(ctx, "cert.CertListCmd", func(child context.Context, client *httpclient.Client) error {
		list, err := client.ListCerts(child, cert.CertListRequest{
			OffsetLimit: cert.OffsetLimit{Offset: cmd.Offset, Limit: cmd.Limit},
			IsCA:        cmd.CA,
			Enabled:     cmd.Enabled,
			Valid:       cmd.Valid,
			Tags:        cmd.Tags,
		})
		if err != nil {
			return err
		}

		// With debugging, print the response
		if debug {
			fmt.Println(list)
			return nil
		}

		// Certificates table and summary
		rows := make([]certRow, 0, len(list.Body))
		for _, c := range list.Body {
			rows = append(rows, certRow(c))
		}
		if _, err := tui.TableFor[certRow](tui.SetWidth(width)).Write(os.Stdout, rows...); err != nil {
			return err
		}
		_, err = tui.TableSummary("certificates", uint(list.Count), uint(len(list.Body)), list.Offset, list.Limit).Write(os.Stdout)
		return err
	})
}

func (cmd *CertGetCmd) Run(ctx server.Cmd) error {
	// A private key is only printed to a terminal when it's asked for
	if cmd.Key && !cmd.Show && term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("the private key isn't printed to a terminal: redirect it to a file, or set --show")
	}

	get := func(child context.Context, client *httpclient.Client) error {
		var bundle *cert.CertBundle
		var err error
		if cmd.Key {
			bundle, err = client.GetPrivateKey(child, key(cmd.Name, cmd.Serial), cert.GetCertRequest{Chain: cmd.Chain})
		} else {
			bundle, err = client.GetCert(child, key(cmd.Name, cmd.Serial), cert.GetCertRequest{Chain: cmd.Chain})
		}
		if err != nil {
			return err
		}
		return writeBundle(os.Stdout, bundle, cmd.Comments)
	}
	if cmd.Key {
		return withKeyClient(ctx, "cert.CertGetCmd", get)
	}
	return withClient(ctx, "cert.CertGetCmd", get)
}

func (cmd *CertCreateCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "cert.CertCreateCmd", func(child context.Context, client *httpclient.Client) error {
		created, err := client.CreateCert(child, cert.CreateCertRequest{
			Name:    cmd.Name,
			Expiry:  cmd.Expiry,
			Subject: cmd.subject(),
			SAN:     cmd.SAN,
			Tags:    cmd.Tags,
		}, key(cmd.CA, cmd.CASerial))
		return printCert(ctx, "created certificate", created, err)
	})
}

func (cmd *CertRenewCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "cert.CertRenewCmd", func(child context.Context, client *httpclient.Client) error {
		renewed, err := client.RenewCert(child, key(cmd.Name, cmd.Serial), cert.RenewCertRequest{Expiry: cmd.Expiry, Subject: cmd.subject()})
		return printCert(ctx, "renewed certificate", renewed, err)
	})
}

func (cmd *CertUpdateCmd) Run(ctx server.Cmd) error {
	meta := cert.CertMeta{Enabled: cmd.Enabled}
	switch {
	case cmd.ClearTags && len(cmd.Tags) > 0:
		return fmt.Errorf("set --tag or --clear-tags, not both")
	case cmd.ClearTags:
		meta.Tags = []string{}
	case len(cmd.Tags) > 0:
		meta.Tags = cmd.Tags
	case cmd.Enabled == nil:
		return fmt.Errorf("nothing to update: set --enabled, --no-enabled, --tag or --clear-tags")
	}
	return withClient(ctx, "cert.CertUpdateCmd", func(child context.Context, client *httpclient.Client) error {
		updated, err := client.UpdateCert(child, key(cmd.Name, cmd.Serial), meta)
		return printCert(ctx, "updated certificate", updated, err)
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// printCert prints what was done to a certificate, with its name and serial,
// or the certificate with debugging
func printCert(ctx server.Cmd, done string, c *cert.Certificate, err error) error {
	if err != nil {
		return err
	}
	if ctx.IsDebug() {
		fmt.Println(c)
		return nil
	}
	fmt.Println(done, c.Name, c.Serial)
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// TABLE

func (r certRow) Header() []string {
	return []string{"Name", "Serial", "Type", "Signer", "Expires", "State", "Tags"}
}

func (r certRow) Width(int) int {
	return 0
}

func (r certRow) Cell(col int) tui.CellText {
	c := cert.Certificate(r)
	switch col {
	case 0:
		return c.Name
	case 1:
		return c.Serial
	case 2:
		return certType(c)
	case 3:
		if c.Signer == nil {
			return ""
		}
		return c.Signer.Name
	case 4:
		if c.NotAfter.IsZero() {
			return ""
		}
		return c.NotAfter.Local().Format(time.DateTime)
	case 5:
		return certState(c)
	case 6:
		return strings.Join(c.EffectiveTags, ", ")
	default:
		return ""
	}
}
