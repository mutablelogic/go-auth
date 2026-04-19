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
	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	server "github.com/mutablelogic/go-server"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type TokenStore struct {
	ctx server.Cmd
}

var _ auth.TokenStore = (*TokenStore)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewTokenStore(ctx server.Cmd) *TokenStore {
	return &TokenStore{ctx: ctx}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (s *TokenStore) StoreToken(endpoint, issuer string, token *oauth2.Token) error {
	provider := storedProvider(s.ctx, endpoint)
	return storeToken(s.ctx, endpoint, issuer, provider, token)
}

func (s *TokenStore) Token(endpoint string) (*oauth2.Token, string, error) {
	token, err := storedToken(s.ctx, endpoint)
	if err != nil || token == nil {
		return token, "", err
	}
	return token, s.tokenIssuer(endpoint), nil
}

func (s *TokenStore) tokenIssuer(endpoint string) string {
	return s.ctx.GetString(issuerStoreKey(endpoint))
}
