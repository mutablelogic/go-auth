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

package main

import (
	"io/fs"

	// Packages
	app "github.com/mutablelogic/go-auth/build/app.wasm"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
)

func registerUIHandlers(router *httprouter.Router) error {
	root, err := fs.Sub(app.FrontendFS, ".")
	if err != nil {
		return err
	}
	return router.RegisterFS("/", root, false, nil)
}
