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
	"sync"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// locks are the locks of credentials' keys, in the process
var locks sync.Map

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Lock locks the key of a credential, in the process, and returns the
// function which unlocks it. A sign-in is stored under its key's lock, so
// code which reads a credential, and stores it again, such as a token which
// it refreshed, does so under the lock, and doesn't replace a sign-in which
// was stored after it read it. A credential which another process stores
// isn't locked.
func Lock(key string) func() {
	value, _ := locks.LoadOrStore(key, new(sync.Mutex))
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
