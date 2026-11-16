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

//go:build !unix && !windows

package httpclient

import (
	"os"
)

// lockFile doesn't lock the file, as there's no way to, so only this
// process's own are serialized
func lockFile(*os.File) error { return nil }

// unlockFile doesn't unlock the file
func unlockFile(*os.File) error { return nil }

// privateMode returns whether files' modes say who can read them
const privateMode = false
