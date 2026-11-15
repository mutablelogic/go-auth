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

//go:build !client && frontend

package cmd

import (
	"io/fs"
	"mime"

	// Packages
	frontend "github.com/mutablelogic/go-auth/frontend"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
)

// builtIn is whether the web UI is built in, which it is, with the
// "frontend" tag
const builtIn = true

// registerFS registers the web UI, from its root. Its fonts are served with
// their type, which Go doesn't know, and which a system's own types mayn't
// have.
func registerFS(router *httprouter.Router) error {
	if err := mime.AddExtensionType(".woff2", "font/woff2"); err != nil {
		return err
	}
	sub, err := fs.Sub(frontend.EmbedFS, "app/dist")
	if err != nil {
		return err
	}
	return router.RegisterFS("/", sub, false, nil)
}
