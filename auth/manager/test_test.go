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

package manager_test

import (
	"context"
	"strings"
	"testing"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	localprovider "github.com/mutablelogic/go-auth/auth/provider/local"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	authtest "github.com/mutablelogic/go-auth/auth/test"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var (
	shared *manager.Manager
)

const (
	DefaultIssuer     = "https://issuer/"
	DefaultSessionTTL = 15 * time.Minute
	apiKeyPrefix      = "test_"
)

type apiKeyHooks struct{}

func (apiKeyHooks) OnKeyCreate(_ context.Context, _ schema.Key) (string, error) {
	return apiKeyPrefix, nil
}

func (apiKeyHooks) OnKeyValidate(_ context.Context, token string) (string, error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, apiKeyPrefix) {
		return "", auth.ErrBadParameter.With("token prefix is invalid")
	}
	return strings.TrimPrefix(token, apiKeyPrefix), nil
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func TestMain(m *testing.M) {
	key, err := authcrypto.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	provider, err := localprovider.New(DefaultIssuer, key)
	if err != nil {
		panic(err)
	}

	authtest.Main(m, func(manager *manager.Manager) (func(), error) {
		shared = manager
		return func() {
			shared = nil
		}, nil
	},
		manager.WithSigner("test-main", key),
		manager.WithProvider(provider),
		manager.WithHooks(apiKeyHooks{}),
		manager.WithTTL(DefaultSessionTTL, schema.DefaultRefreshTTL),
	)
}
