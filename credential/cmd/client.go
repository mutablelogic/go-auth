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

package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	// Packages
	httpclient "github.com/mutablelogic/go-auth/credential/httpclient"
	client "github.com/mutablelogic/go-client"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	server "github.com/mutablelogic/go-server"
	term "golang.org/x/term"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withClient calls fn with a client of the credential API, at the endpoint
// of the command's HTTP flags, in a span
func withClient(ctx server.Cmd, span string, fn func(context.Context, *httpclient.Client) error) (err error) {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	return runClient(ctx, span, endpoint, opts, fn)
}

// withSecretClient calls fn with a client of the credential API, as
// withClient does, for a request or a response which has a secret, such as
// a passphrase, or a credential's value. Its options are the command's,
// without --verbose's trace, which would print the secret, so --debug
// traces the requests, without their bodies.
func withSecretClient(ctx server.Cmd, span string, fn func(context.Context, *httpclient.Client) error) error {
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
	client, err := httpclient.New(endpoint, opts...)
	if err != nil {
		return err
	}
	child, endSpan := otel.StartSpan(ctx.Tracer(), ctx.Context(), span)
	defer func() { endSpan(err) }()
	return fn(child, client)
}

// readSecret reads a value from stdin, prompting for it and hiding what is
// typed on a terminal, and removes a single trailing line ending
func readSecret(prompt string) ([]byte, error) {
	var value []byte
	var err error
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		value, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		value, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		return nil, err
	}
	return trimNewline(value), nil
}

// writeCredential writes a credential which is a JSON string as text,
// unless jsonString is set, and any other credential as indented JSON, as
// it is, so its numbers aren't changed
func writeCredential(w io.Writer, credential json.RawMessage, jsonString bool) error {
	var value string
	if err := json.Unmarshal(credential, &value); err == nil && !jsonString {
		_, err := fmt.Fprintln(w, value)
		return err
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, credential, "", "  "); err != nil {
		return err
	}
	indented.WriteByte('\n')
	_, err := indented.WriteTo(w)
	return err
}

// trimNewline removes a single trailing line ending, which echo and most
// editors add, and keeps any other whitespace, which may be part of the value
func trimNewline(value []byte) []byte {
	if bytes.HasSuffix(value, []byte("\r\n")) {
		return value[:len(value)-2]
	}
	return bytes.TrimSuffix(value, []byte("\n"))
}
