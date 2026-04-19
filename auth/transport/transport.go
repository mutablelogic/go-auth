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

package transport

import (
	"net/http"
	"strings"

	// Packages
	transport "github.com/mutablelogic/go-client/pkg/transport"
)

// TokenTransport returns a transport wrapper which injects the stored bearer
// token for the specified endpoint into every outgoing request.
func TokenTransport(endpoint string, tokenstore TokenStore) func(http.RoundTripper) http.RoundTripper {
	return func(parent http.RoundTripper) http.RoundTripper {
		return transport.NewToken(parent, func() string {
			if tokenstore == nil || endpoint == "" {
				return ""
			}
			token, _, err := tokenstore.Token(endpoint)
			if err != nil || token == nil || strings.TrimSpace(token.AccessToken) == "" {
				return ""
			}
			return token.Type() + " " + token.AccessToken
		})
	}
}
