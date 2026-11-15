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

// Package frontend is go-auth's web UI: its modules, such as Credentials,
// which the package @mutablelogic/go-auth exports, and the auth server's
// app, which make builds into app/dist, and which a command built with the
// "frontend" tag embeds, as EmbedFS. It's tracked, so go mod tidy, which
// reads every tag's imports, finds it before the UI is built.
package frontend
