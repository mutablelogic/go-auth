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

//go:build !client

// Package cmd serves the web UI, and the server's configuration, which it
// reads, beside the API, when the server is built with the "frontend" tag,
// which embeds the UI, once it's built, with npm, into frontend/dist, which
// make does. Without it, such as with go install, the server serves its API
// and configuration, without the UI.
package cmd

import (
	"context"
	"log/slog"

	// Packages
	server "github.com/mutablelogic/go-server"
	config "github.com/mutablelogic/go-server/config"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Flags are the web UI's flags
type Flags struct {
	UI bool `name:"ui" help:"Serve the web UI from this server, when it's built in." default:"true" negatable:""`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// SignInPath is the path of the web UI's sign-in page, which signs in with
// the providers, and returns to its return parameter
const SignInPath = "/login.html"

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// BuiltIn returns whether the web UI is built in, with the "frontend" tag
func BuiltIn() bool {
	return builtIn
}

// SignIn returns the path of the web UI's sign-in page, when it's built in,
// and served, or else nothing
func (f *Flags) SignIn() string {
	if !builtIn || !f.UI {
		return ""
	}
	return SignInPath
}

// RegisterUI registers the server's configuration, at /config.json, and the
// web UI, at /, when it's built in, unless it isn't to be served. When
// openapi is true, the configuration says where the API's documentation is.
// The options add the modules' sections to the configuration, such as what
// the credential manager can do. Returns true when the UI is served, so the
// server doesn't register its own handler of /.
func (f *Flags) RegisterUI(ctx server.Cmd, log *slog.Logger, router *httprouter.Router, openapi bool, opts ...config.Opt) (bool, error) {
	if err := config.RegisterHandler(router, config.New(ctx, router, openapi), opts...); err != nil {
		return false, err
	} else if !f.UI {
		return false, nil
	} else if !builtIn {
		log.DebugContext(context.Background(), "the web UI isn't built in, so isn't served, which make, with npm, builds it into")
		return false, nil
	}
	log.DebugContext(context.Background(), "registering web UI handlers")
	return true, registerFS(router)
}
