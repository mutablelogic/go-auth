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

package auth

import (
	"testing"

	schema "github.com/mutablelogic/go-auth/auth/schema"
)

func TestDefaultAuthorizationProvider(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		if got := defaultAuthorizationProvider(nil); got != "" {
			t.Fatalf("defaultAuthorizationProvider(nil) = %q, want empty", got)
		}
	})

	t.Run("single", func(t *testing.T) {
		config := schema.PublicClientConfigurations{
			"local": {},
		}
		if got := defaultAuthorizationProvider(config); got != "local" {
			t.Fatalf("defaultAuthorizationProvider(single) = %q, want %q", got, "local")
		}
	})

	t.Run("multiple", func(t *testing.T) {
		config := schema.PublicClientConfigurations{
			"local":  {},
			"google": {},
		}
		if got := defaultAuthorizationProvider(config); got != "" {
			t.Fatalf("defaultAuthorizationProvider(multiple) = %q, want empty", got)
		}
	})
}
