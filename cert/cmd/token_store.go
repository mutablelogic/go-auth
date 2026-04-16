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

package certmanager

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	server "github.com/mutablelogic/go-server"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type CmdTokenStore struct {
	ctx server.Cmd
}

var _ auth.TokenStore = (*CmdTokenStore)(nil)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const issuerStoreKeyPrefix = "auth.issuer."
const tokenStoreKeyPrefix = "auth.token."

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewCmdTokenStore(ctx server.Cmd) *CmdTokenStore {
	return &CmdTokenStore{ctx: ctx}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (s *CmdTokenStore) StoreToken(endpoint, issuer string, token *oauth2.Token) error {
	if s == nil || s.ctx == nil || token == nil {
		return nil
	}
	endpoint = strings.TrimSpace(endpoint)
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	clone := *token
	if err := s.ctx.Set(tokenStoreKey(issuer), clone); err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	if endpoint != "" {
		if err := s.ctx.Set(issuerStoreKey(endpoint), issuer); err != nil {
			return fmt.Errorf("store token issuer: %w", err)
		}
	}
	return nil
}

func (s *CmdTokenStore) Token(endpoint string) (*oauth2.Token, string, error) {
	if s == nil || s.ctx == nil {
		return nil, "", nil
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, "", nil
	}
	issuer := strings.TrimSpace(s.ctx.GetString(issuerStoreKey(endpoint)))
	if issuer != "" {
		if token, err := decodeStoredToken(s.ctx.Get(tokenStoreKey(issuer))); err != nil {
			return nil, "", err
		} else if token != nil {
			return token, issuer, nil
		}
	}
	token, err := decodeStoredToken(s.ctx.Get(tokenStoreKey(endpoint)))
	if err != nil {
		return nil, "", err
	}
	return token, issuer, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func decodeStoredToken(value any) (*oauth2.Token, error) {
	switch token := value.(type) {
	case nil:
		return nil, nil
	case oauth2.Token:
		clone := token
		return &clone, nil
	case *oauth2.Token:
		if token == nil {
			return nil, nil
		}
		clone := *token
		return &clone, nil
	default:
		data, err := json.Marshal(token)
		if err != nil {
			return nil, fmt.Errorf("decode stored token: %w", err)
		}
		var decoded oauth2.Token
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("decode stored token: %w", err)
		}
		if strings.TrimSpace(decoded.AccessToken) == "" {
			return nil, nil
		}
		return &decoded, nil
	}
}

func tokenStoreKey(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = "default"
	}
	return tokenStoreKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte(issuer))
}

func issuerStoreKey(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = "default"
	}
	return issuerStoreKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte(endpoint))
}
