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
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/ldap/httpclient"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	server "github.com/mutablelogic/go-server"
	term "golang.org/x/term"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withClient calls fn with a client of the LDAP API, at the endpoint of the
// command's HTTP flags, in a span
func withClient(ctx server.Cmd, span string, fn func(context.Context, *httpclient.Client) error) (err error) {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	c, err := httpclient.New(endpoint, opts...)
	if err != nil {
		return err
	}
	child, endSpan := otel.StartSpan(ctx.Tracer(), ctx.Context(), span)
	defer func() { endSpan(err) }()
	return fn(child, c)
}

// parseAttrs returns the attributes, which are name=value, repeated for
// more values of a name. A name without a value, name=, has no values,
// which deletes it in an update.
func parseAttrs(args []string) (schema.Attrs, error) {
	attrs := schema.Attrs{}
	for _, arg := range args {
		name, value, ok := strings.Cut(arg, "=")
		if name = strings.TrimSpace(name); !ok || name == "" {
			return nil, auth.ErrBadParameter.Withf("%q isn't an attribute: use name=value", arg)
		}
		if _, exists := attrs[name]; !exists {
			attrs[name] = []string{}
		}
		if value != "" {
			attrs[name] = append(attrs[name], value)
		}
	}
	return attrs, nil
}

// printObject prints the object, as LDIF, or JSON with debugging, after
// what was done to it, when it's set, as a comment
func printObject(ctx server.Cmd, done string, object fmt.Stringer, ldif string) {
	if done != "" {
		fmt.Println("#", done)
	}
	if ctx.IsDebug() {
		fmt.Println(object)
	} else {
		fmt.Print(ldif)
	}
}

// readPassword returns a password: prompted for, without echoing it, in a
// terminal, or the next line of the input otherwise
func readPassword(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := stdin.ReadString('\n')
		if err != nil && line == "" {
			return "", auth.ErrBadParameter.Withf("no password: %v", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(password), err
}

// stdin reads passwords, one a line, when the input isn't a terminal
var stdin = bufio.NewReader(os.Stdin)
