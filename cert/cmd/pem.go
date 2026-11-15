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
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// writeBundle writes the certificate as PEM, after its private key, when
// it has one, and before its chain, when it has one, with the details of
// each as comments before them when comments is true
func writeBundle(w io.Writer, bundle *cert.CertBundle, comments bool) error {
	if len(bundle.Key) > 0 {
		if err := writeBlock(w, bundle.Certificate, "private key", cert.PemTypePrivateKey, bundle.Key, comments); err != nil {
			return err
		}
	}
	if err := writeBlock(w, bundle.Certificate, certType(bundle.Certificate), cert.PemTypeCertificate, bundle.Cert, comments); err != nil {
		return err
	}
	for _, issuer := range bundle.Chain {
		if err := writeBlock(w, issuer, certType(issuer), cert.PemTypeCertificate, issuer.Cert, comments); err != nil {
			return err
		}
	}
	return nil
}

// writeBlock writes a PEM block, with the certificate's details as comments
// before it when comments is true
func writeBlock(w io.Writer, c cert.Certificate, what, blockType string, data []byte, comments bool) error {
	if len(data) == 0 {
		return fmt.Errorf("%s %q has no %s", certType(c), c.Name, what)
	}
	if comments {
		for _, line := range commentLines(c, what) {
			if _, err := fmt.Fprintln(w, "# "+line); err != nil {
				return err
			}
		}
	}
	return pem.Encode(w, &pem.Block{Type: blockType, Bytes: data})
}

// commentLines are the certificate's details
func commentLines(c cert.Certificate, what string) []string {
	or := func(value string) string {
		if value = strings.TrimSpace(value); value == "" {
			return "-"
		}
		return value
	}
	var subject, signer string
	if c.Subject != nil {
		subject = types.Value(c.Subject.Name)
	}
	if c.Signer != nil {
		signer = c.Signer.Name
	}
	return []string{
		what + ": " + or(c.Name) + " " + or(c.Serial),
		"subject: " + or(subject),
		"signer: " + or(signer),
		"san: " + or(strings.Join(c.SAN, ", ")),
		"tags: " + or(strings.Join(c.EffectiveTags, ", ")),
		"state: " + certState(c),
		"not before: " + formatTime(c.NotBefore),
		"not after: " + formatTime(c.NotAfter),
	}
}

// certType is what the certificate is
func certType(c cert.Certificate) string {
	switch {
	case c.IsRoot():
		return "root"
	case c.IsCA:
		return "certificate authority"
	default:
		return "certificate"
	}
}

// certState is whether the certificate is enabled, and valid now
func certState(c cert.Certificate) string {
	state := []string{}
	if c.Enabled != nil && !*c.Enabled {
		state = append(state, "disabled")
	} else {
		state = append(state, "enabled")
	}
	now := time.Now()
	switch {
	case !c.NotAfter.IsZero() && !now.Before(c.NotAfter):
		state = append(state, "expired")
	case !c.NotBefore.IsZero() && now.Before(c.NotBefore):
		state = append(state, "not yet valid")
	}
	return strings.Join(state, ", ")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
