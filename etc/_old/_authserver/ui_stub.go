//go:build !uiassets

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

package main

import (
	"fmt"

	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
)

func registerUIHandlers(_ *httprouter.Router) error {
	return fmt.Errorf("embedded UI assets are not built; run make wasm && make cmd or start authserver with --no-ui")
}
