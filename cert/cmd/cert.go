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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	// Packages
	certpkg "github.com/mutablelogic/go-auth/cert/cert"
	certclient "github.com/mutablelogic/go-auth/cert/httpclient"
	schema "github.com/mutablelogic/go-auth/cert/schema"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

var certmanagerOutput io.Writer = os.Stdout

type CertCommands struct {
	Cert       GetCertCommand    `cmd:"" name:"cert" help:"Get certificate." group:"CERTIFICATE MANAGER"`
	Certs      ListCertsCommand  `cmd:"" name:"certs" help:"List certificates." group:"CERTIFICATE MANAGER"`
	CreateCert CreateCertCommand `cmd:"" name:"cert-create" help:"Create certificate." group:"CERTIFICATE MANAGER"`
	RenewCert  RenewCertCommand  `cmd:"" name:"cert-renew" help:"Renew certificate." group:"CERTIFICATE MANAGER"`
	UpdateCert UpdateCertCommand `cmd:"" name:"cert-update" help:"Update certificate." group:"CERTIFICATE MANAGER"`
}

type GetCertCommand struct {
	Name     string `arg:"" name:"name" help:"Certificate name"`
	Serial   string `arg:"" optional:"" name:"serial" help:"Certificate serial number. Omit to use the latest certificate version."`
	Chain    bool   `name:"chain" help:"Include the issuer chain in the output."`
	Private  bool   `name:"private" help:"Include the private key in the output."`
	Comments bool   `name:"comments" help:"Include certificate metadata comments before each PEM block." default:"true" negatable:""`
}

type ListCertsCommand schema.CertListRequest

type CreateCertCommand struct {
	Name     string        `arg:"" name:"name" help:"Certificate name"`
	CAName   string        `arg:"" name:"ca" help:"Certificate authority name"`
	CASerial string        `arg:"" optional:"" name:"serial" help:"Certificate authority serial number. Omit to use the latest CA version."`
	Expiry   time.Duration `name:"expiry" help:"Certificate lifetime. Zero uses the server default."`
	SAN      []string      `name:"san" help:"Subject alternative name entry. Repeat to set multiple DNS names, wildcard DNS names, or IP addresses."`
	Tags     []string      `name:"tag" help:"Tag to apply to the certificate. Repeat to set multiple tags."`
	certSubjectFlags
}

type UpdateCertCommand struct {
	Name      string   `arg:"" name:"name" help:"Certificate name"`
	Serial    string   `arg:"" optional:"" name:"serial" help:"Certificate serial number. Omit to use the latest certificate version."`
	Enable    bool     `name:"enable" help:"Enable the certificate."`
	Disable   bool     `name:"disable" help:"Disable the certificate."`
	Tags      []string `name:"tags" help:"Replace certificate tags with the provided list. Repeat to set multiple tags."`
	ClearTags bool     `name:"clear-tags" help:"Clear all certificate tags."`
}

type RenewCertCommand struct {
	Name   string        `arg:"" name:"name" help:"Certificate name"`
	Serial string        `arg:"" optional:"" name:"serial" help:"Certificate serial number. Omit to use the latest certificate version."`
	Expiry time.Duration `name:"expiry" help:"Certificate lifetime. Zero preserves the current lifetime, capped by the signer validity."`
	certSubjectFlags
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *GetCertCommand) Run(ctx server.Cmd) error {
	return withUnauthenticatedClient(ctx, func(client *certclient.Client, endpoint string) error {
		bundle, err := client.GetCert(ctx.Context(), schema.CertKey{
			Name:   strings.TrimSpace(cmd.Name),
			Serial: strings.TrimSpace(cmd.Serial),
		}, cmd.Chain, cmd.Private)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			return writeCertBundleJSON(certmanagerOutput, bundle)
		}
		return writeCertBundlePEM(certmanagerOutput, bundle, cmd.Private, cmd.Comments)
	})
}

func (cmd *ListCertsCommand) Run(ctx server.Cmd) error {
	return withUnauthenticatedClient(ctx, func(client *certclient.Client, endpoint string) error {
		certs, err := client.ListCerts(ctx.Context(), schema.CertListRequest(*cmd))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(certmanagerOutput, certs)
		return err
	})
}

func (cmd *CreateCertCommand) Run(ctx server.Cmd) error {
	return withUnauthenticatedClient(ctx, func(client *certclient.Client, endpoint string) error {
		cert, err := client.CreateCert(ctx.Context(), schema.CreateCertRequest{
			Name:    strings.TrimSpace(cmd.Name),
			Expiry:  cmd.Expiry,
			Subject: cmd.subject(),
			SAN:     append([]string(nil), cmd.SAN...),
			Tags:    append([]string(nil), cmd.Tags...),
		}, schema.CertKey{
			Name:   strings.TrimSpace(cmd.CAName),
			Serial: strings.TrimSpace(cmd.CASerial),
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(certmanagerOutput, cert)
		return err
	})
}

func (cmd *UpdateCertCommand) Run(ctx server.Cmd) error {
	if cmd.Enable && cmd.Disable {
		return fmt.Errorf("cannot set both enable and disable")
	}
	if cmd.ClearTags && len(cmd.Tags) > 0 {
		return fmt.Errorf("cannot set --tag and --clear-tags together")
	}

	meta := schema.CertMeta{}
	if cmd.Enable {
		meta.Enabled = types.Ptr(true)
	} else if cmd.Disable {
		meta.Enabled = types.Ptr(false)
	}
	if cmd.ClearTags {
		meta.Tags = []string{}
	} else if len(cmd.Tags) > 0 {
		meta.Tags = append([]string(nil), cmd.Tags...)
	}

	return withUnauthenticatedClient(ctx, func(client *certclient.Client, endpoint string) error {
		cert, err := client.UpdateCert(ctx.Context(), schema.CertKey{
			Name:   strings.TrimSpace(cmd.Name),
			Serial: strings.TrimSpace(cmd.Serial),
		}, meta)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(certmanagerOutput, cert)
		return err
	})
}

func (cmd *RenewCertCommand) Run(ctx server.Cmd) error {
	req := renewRequest(cmd.Expiry, cmd.subject())

	return withUnauthenticatedClient(ctx, func(client *certclient.Client, endpoint string) error {
		cert, err := client.RenewCert(ctx.Context(), schema.CertKey{
			Name:   strings.TrimSpace(cmd.Name),
			Serial: strings.TrimSpace(cmd.Serial),
		}, req)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(certmanagerOutput, cert)
		return err
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func renewRequest(expiry time.Duration, subject *schema.SubjectMeta) schema.RenewCertRequest {
	return schema.RenewCertRequest{
		Expiry:  expiry,
		Subject: subject,
	}
}

func writeCertBundleJSON(w io.Writer, bundle *schema.CertBundle) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(bundle)
}

func writeCertBundlePEM(w io.Writer, bundle *schema.CertBundle, includePrivate bool, includeComments bool) error {
	if includePrivate {
		if len(bundle.Key) == 0 {
			return fmt.Errorf("missing private key bytes")
		}
		if includeComments {
			if err := writePEMComment(w, bundle.Cert, "private key"); err != nil {
				return err
			}
		}
		if err := writePEMBlock(w, &pem.Block{Type: certpkg.PemTypePrivateKey, Bytes: bundle.Key}); err != nil {
			return err
		}
	}
	if err := writeCertificatePEM(w, bundle.Cert, includeComments); err != nil {
		return err
	}
	for _, cert := range bundle.Chain {
		if err := writeCertificatePEM(w, cert, includeComments); err != nil {
			return err
		}
	}
	return nil
}

func writeCertificatePEM(w io.Writer, cert schema.Cert, includeComments bool) error {
	if len(cert.Cert) == 0 {
		return fmt.Errorf("missing certificate bytes")
	}
	if includeComments {
		if err := writePEMComment(w, cert, pemType(cert)); err != nil {
			return err
		}
	}
	return writePEMBlock(w, &pem.Block{Type: certpkg.PemTypeCertificate, Bytes: cert.Cert})
}

func writePEMComment(w io.Writer, cert schema.Cert, blockType string) error {
	for _, line := range pemCommentLines(cert, blockType) {
		if _, err := fmt.Fprintf(w, "# %s\n", line); err != nil {
			return err
		}
	}
	return nil
}

func writePEMBlock(w io.Writer, block *pem.Block) error {
	if err := pem.Encode(w, block); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}

func pemCommentLines(cert schema.Cert, blockType string) []string {
	return []string{
		"subject: " + pemSubjectName(cert),
		"serial: " + pemSerial(cert),
		"san: " + pemSAN(cert),
		"tags: " + pemTags(cert),
		"type: " + pemTypeLine(cert, blockType),
		"signer: " + pemSignerName(cert),
		"not_before: " + pemTime(cert.NotBefore),
		"not_after: " + pemTime(cert.NotAfter),
		"created: " + pemTime(cert.Ts),
	}
}

func pemSerial(cert schema.Cert) string {
	if serial := strings.TrimSpace(cert.Serial); serial != "" {
		return serial
	}
	return "-"
}

func pemSubjectName(cert schema.Cert) string {
	if cert.Subject == nil {
		return "-"
	}
	if cert.Subject.Name != nil && strings.TrimSpace(*cert.Subject.Name) != "" {
		return strings.TrimSpace(*cert.Subject.Name)
	}
	return "-"
}

func pemSAN(cert schema.Cert) string {
	if len(cert.SAN) == 0 {
		return "-"
	}
	return strings.Join(cert.SAN, ", ")
}

func pemTags(cert schema.Cert) string {
	if len(cert.EffectiveTags) == 0 {
		return "-"
	}
	return strings.Join(cert.EffectiveTags, ", ")
}

func pemType(cert schema.Cert) string {
	if cert.IsRoot() {
		return "root"
	}
	if cert.IsCA {
		return "certificate authority"
	}
	return "certificate"
}

func pemTypeLine(cert schema.Cert, blockType string) string {
	parts := []string{blockType}
	if cert.Enabled != nil {
		if *cert.Enabled {
			parts = append(parts, "enabled")
		} else {
			parts = append(parts, "disabled")
		}
	}
	if pemIsExpired(cert) {
		parts = append(parts, "expired")
	} else if pemIsValid(cert) {
		parts = append(parts, "valid")
	}
	return strings.Join(parts, ", ")
}

func pemIsValid(cert schema.Cert) bool {
	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		return false
	}
	now := time.Now().UTC()
	return !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
}

func pemIsExpired(cert schema.Cert) bool {
	if cert.NotAfter.IsZero() {
		return false
	}
	return !time.Now().UTC().Before(cert.NotAfter)
}

func pemSignerName(cert schema.Cert) string {
	if cert.Signer == nil || strings.TrimSpace(cert.Signer.Name) == "" {
		return "-"
	}
	return strings.TrimSpace(cert.Signer.Name)
}

func pemTime(ts time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	return ts.UTC().Format(time.RFC3339)
}
