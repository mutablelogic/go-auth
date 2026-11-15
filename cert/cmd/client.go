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
	"os"
	"strings"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	httpclient "github.com/mutablelogic/go-auth/cert/httpclient"
	client "github.com/mutablelogic/go-client"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// subjectFlags are a certificate's subject, which replace the fields of its
// signer's, or of the version which is renewed
type subjectFlags struct {
	Org           string `name:"organization" help:"Subject organization name"`
	Unit          string `name:"organizational-unit" help:"Subject organizational unit"`
	Country       string `name:"country" help:"Subject country code"`
	City          string `name:"city" help:"Subject locality or city"`
	State         string `name:"state" help:"Subject state or province"`
	StreetAddress string `name:"street-address" help:"Subject street address"`
	PostalCode    string `name:"postal-code" help:"Subject postal code"`
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withClient calls fn with a client of the certificate API, at the endpoint
// of the command's HTTP flags, in a span
func withClient(ctx server.Cmd, span string, fn func(context.Context, *httpclient.Client) error) error {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	return runClient(ctx, span, endpoint, opts, fn)
}

// withKeyClient calls fn with a client of the certificate API, as
// withClient does, for a response with a private key. Its options are the
// command's, without --verbose's trace, which would print the key, so
// --debug traces the requests, without their bodies.
func withKeyClient(ctx server.Cmd, span string, fn func(context.Context, *httpclient.Client) error) error {
	endpoint, _, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	opts := []client.ClientOpt{client.OptTracer(ctx.Tracer())}
	if timeout := ctx.HTTPTimeout(); timeout > 0 {
		opts = append(opts, client.OptTimeout(timeout))
	}
	if ctx.IsDebug() {
		opts = append(opts, client.OptTrace(os.Stderr, false))
	}
	return runClient(ctx, span, endpoint, opts, fn)
}

// runClient calls fn with a client of the endpoint, with the options, in a
// span
func runClient(ctx server.Cmd, span, endpoint string, opts []client.ClientOpt, fn func(context.Context, *httpclient.Client) error) (err error) {
	c, err := httpclient.New(endpoint, opts...)
	if err != nil {
		return err
	}
	child, endSpan := otel.StartSpan(ctx.Tracer(), ctx.Context(), span)
	defer func() { endSpan(err) }()
	return fn(child, c)
}

// key is a certificate's version, or its latest version without a serial
func key(name, serial string) cert.CertKey {
	return cert.CertKey{Name: strings.TrimSpace(name), Serial: strings.TrimSpace(serial)}
}

// subject is the subject in the flags, or nil when none is set
func (flags subjectFlags) subject() *cert.SubjectMeta {
	value := func(s string) *string {
		if s = strings.TrimSpace(s); s != "" {
			return types.Ptr(s)
		}
		return nil
	}
	subject := cert.SubjectMeta{
		Org:           value(flags.Org),
		Unit:          value(flags.Unit),
		Country:       value(flags.Country),
		City:          value(flags.City),
		State:         value(flags.State),
		StreetAddress: value(flags.StreetAddress),
		PostalCode:    value(flags.PostalCode),
	}
	if subject == (cert.SubjectMeta{}) {
		return nil
	}
	return &subject
}
