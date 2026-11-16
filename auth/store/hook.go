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

package store

import (
	"context"
	"strings"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// AllowDomains returns a hook, which only allows identities with a
// verified email address at one of the domains, such as example.com, in
// any case
func AllowDomains(domains ...string) Hook {
	return func(_ context.Context, identity *schema.Identity) error {
		if _, domain, ok := strings.Cut(identity.Email, "@"); ok && identity.EmailVerified {
			for _, allowed := range domains {
				if strings.EqualFold(domain, strings.TrimPrefix(allowed, "@")) {
					return nil
				}
			}
		}
		return httpresponse.ErrForbidden.Withf("Only those with a verified email address at %s can sign in", strings.Join(domains, ", "))
	}
}
