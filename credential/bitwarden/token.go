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

package bitwarden

import (
	"encoding/base64"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// accessToken is a Secrets Manager machine account's access token, which is
// "0.<id>.<client secret>:<encryption key>"
type accessToken struct {
	id     string
	secret string
	key    *key
}

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// parseAccessToken parses an access token, and derives its encryption key
func parseAccessToken(value string) (*accessToken, error) {
	first, encoded, ok := strings.Cut(value, ":")
	if !ok {
		return nil, auth.ErrBadParameter.With("access token doesn't contain an encryption key")
	}
	parts := strings.Split(first, ".")
	if len(parts) != 3 {
		return nil, auth.ErrBadParameter.With("access token has the wrong number of parts")
	} else if parts[0] != "0" {
		return nil, auth.ErrBadParameter.With("access token is the wrong version")
	} else if !isUUID(parts[1]) {
		return nil, auth.ErrBadParameter.With("access token has an invalid identifier")
	}

	// The encryption key is 16 bytes, in base64, which may not be padded
	secret, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil {
		return nil, auth.ErrBadParameter.Withf("access token encryption key: %w", err)
	} else if len(secret) != 16 {
		return nil, auth.ErrBadParameter.Withf("access token encryption key is %d bytes, not 16", len(secret))
	}
	key, err := deriveShareableKey(secret, "accesstoken", "sm-access-token")
	if err != nil {
		return nil, auth.ErrInternalServerError.Withf("access token encryption key: %w", err)
	}

	// Return success
	return &accessToken{id: strings.ToLower(parts[1]), secret: parts[2], key: key}, nil
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// isUUID returns true if the value is a UUID, in its 8-4-4-4-12 hex form
func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}
