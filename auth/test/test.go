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

package test

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	// Packages
	uuid "github.com/google/uuid"
	managerpkg "github.com/mutablelogic/go-auth/auth/manager"
	providerpkg "github.com/mutablelogic/go-auth/auth/provider"
	localprovider "github.com/mutablelogic/go-auth/auth/provider/local"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
	pg "github.com/mutablelogic/go-pg"
	pgtest "github.com/mutablelogic/go-pg/pkg/test"
)

const (
	DefaultIssuer     = "http://localhost:8084/api"
	DefaultSessionTTL = 15 * time.Minute
)

type Conn = pgtest.Conn

type Manager struct {
	*managerpkg.Manager
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Schema     string
}

type ManagerOpt func(*managerOptions) error

type managerOptions struct {
	schema               string
	issuer               string
	sessionTTL           time.Duration
	privateKey           *rsa.PrivateKey
	providers            []providerpkg.Provider
	managerOpts          []managerpkg.Opt
	includeLocalProvider bool
}

func Main(m *testing.M, conn *Conn) {
	pgtest.Main(m, conn)
}

func NewManager(t *testing.T, conn *Conn, opts ...ManagerOpt) *Manager {
	t.Helper()
	if conn == nil {
		t.Fatal("conn is required")
	}

	options := defaultManagerOptions()
	if err := options.apply(opts...); err != nil {
		t.Fatal(err)
	}
	if options.privateKey == nil {
		key, err := authcrypto.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		options.privateKey = key
	}

	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	managerOpts := []managerpkg.Opt{
		managerpkg.WithSchema(options.schema),
		managerpkg.WithPrivateKey(options.privateKey),
		managerpkg.WithSessionTTL(options.sessionTTL),
	}
	if options.includeLocalProvider {
		provider, err := localprovider.New(options.issuer, options.privateKey)
		if err != nil {
			t.Fatal(err)
		}
		managerOpts = append(managerOpts, managerpkg.WithProvider(provider))
	}
	for _, provider := range options.providers {
		managerOpts = append(managerOpts, managerpkg.WithProvider(provider))
	}
	managerOpts = append(managerOpts, options.managerOpts...)

	mgr, err := managerpkg.New(context.Background(), c, managerOpts...)
	if err != nil {
		t.Fatal(err)
	}

	harness := &Manager{
		Manager:    mgr,
		PrivateKey: options.privateKey,
		Issuer:     options.issuer,
		Schema:     options.schema,
	}
	t.Cleanup(func() {
		if err := harness.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		if err := pg.SchemaDrop(context.Background(), c, options.schema); err != nil {
			t.Error(err)
		}
	})

	return harness
}

func (m *Manager) Close() error {
	if m == nil || m.Manager == nil {
		return nil
	}
	return m.Manager.Close()
}

func WithSchema(schema string) ManagerOpt {
	return func(o *managerOptions) error {
		schema = strings.TrimSpace(schema)
		if schema == "" {
			return fmt.Errorf("schema name cannot be empty")
		}
		o.schema = schema
		return nil
	}
}

func WithIssuer(issuer string) ManagerOpt {
	return func(o *managerOptions) error {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" {
			return fmt.Errorf("issuer cannot be empty")
		}
		o.issuer = issuer
		return nil
	}
}

func WithSessionTTL(ttl time.Duration) ManagerOpt {
	return func(o *managerOptions) error {
		if ttl <= 0 {
			return fmt.Errorf("session TTL must be positive")
		}
		o.sessionTTL = ttl
		return nil
	}
}

func WithPrivateKey(key *rsa.PrivateKey) ManagerOpt {
	return func(o *managerOptions) error {
		if key == nil {
			return fmt.Errorf("private key is required")
		}
		o.privateKey = key
		return nil
	}
}

func WithProvider(provider providerpkg.Provider) ManagerOpt {
	return func(o *managerOptions) error {
		if provider == nil {
			return fmt.Errorf("provider is required")
		}
		o.providers = append(o.providers, provider)
		return nil
	}
}

func WithManagerOptions(opts ...managerpkg.Opt) ManagerOpt {
	return func(o *managerOptions) error {
		o.managerOpts = append(o.managerOpts, opts...)
		return nil
	}
}

func WithoutLocalProvider() ManagerOpt {
	return func(o *managerOptions) error {
		o.includeLocalProvider = false
		return nil
	}
}

func defaultManagerOptions() managerOptions {
	return managerOptions{
		schema:               newSchemaName(),
		issuer:               DefaultIssuer,
		sessionTTL:           DefaultSessionTTL,
		includeLocalProvider: true,
	}
}

func (o *managerOptions) apply(opts ...ManagerOpt) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(o); err != nil {
			return err
		}
	}
	return nil
}

func newSchemaName() string {
	return "auth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "_")
}
