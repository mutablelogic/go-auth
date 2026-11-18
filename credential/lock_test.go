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

package credential_test

import (
	"testing"
	"time"

	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
)

func Test_Lock(t *testing.T) {
	// A key which is locked isn't locked again until it's unlocked, but
	// another key is
	unlock := credential.Lock("A")
	credential.Lock("B")()
	locked := make(chan struct{})
	go func() {
		credential.Lock("A")()
		close(locked)
	}()
	select {
	case <-locked:
		t.Fatal("locked twice")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("not unlocked")
	}
}
