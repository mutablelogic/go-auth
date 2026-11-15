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

//go:build !client

package credential

import (
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	provider "github.com/mutablelogic/go-auth/credential"
	awscredential "github.com/mutablelogic/go-auth/credential/aws"
	bitwarden "github.com/mutablelogic/go-auth/credential/bitwarden"
	envcredential "github.com/mutablelogic/go-auth/credential/env"
	filecredential "github.com/mutablelogic/go-auth/credential/file"
	pgcredential "github.com/mutablelogic/go-auth/credential/pg"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// FileFlags stores credentials in encrypted files in a directory, which is
// passed to the helpers
type FileFlags struct {
	Passphrase []string `name:"passphrase" env:"${ENV_NAME}_PASSPHRASE" sep:"none" help:"Passphrase for encrypting credentials. Can be specified multiple times, for versions 1, 2 and so on, and the last is used for new credentials."`
}

// PGFlags stores credentials in PostgreSQL, in a pool and schema which are
// passed to the helpers
type PGFlags struct {
	Passphrase []string `name:"passphrase" env:"${ENV_NAME}_PASSPHRASE" sep:"none" help:"Passphrase for encrypting credentials. Can be specified multiple times, for versions 1, 2 and so on, and the last is used for new credentials."`
}

// AWSFlags stores credentials in AWS Secrets Manager. The region and
// credentials are otherwise from the AWS environment variables, such as
// AWS_REGION and AWS_PROFILE, and the shared configuration files.
type AWSFlags struct {
	Region         string `name:"region" help:"AWS region, in place of AWS_REGION"`
	Profile        string `name:"profile" help:"AWS shared configuration profile, in place of AWS_PROFILE"`
	Endpoint       string `name:"endpoint" help:"Secrets Manager endpoint URL, such as for a local emulator"`
	Prefix         string `name:"prefix" env:"AWS_CREDENTIAL_PREFIX" help:"Prefix of secret names, such as myapp/"`
	KMSKey         string `name:"kms-key" env:"AWS_CREDENTIAL_KMS_KEY" help:"KMS key for new secrets, in place of the account's default key"`
	RecoveryWindow *int   `name:"recovery-window" env:"AWS_CREDENTIAL_RECOVERY_WINDOW" help:"Days, from 7 to 30, that a deleted secret can be recovered for, or 0 to delete at once. AWS's default is 30."`
}

// BitwardenFlags stores credentials in Bitwarden Secrets Manager, for a
// machine account
type BitwardenFlags struct {
	AccessToken string `name:"access-token" env:"BWS_ACCESS_TOKEN" help:"Machine account access token"`
	ServerURL   string `name:"server-url" env:"BWS_SERVER_URL" help:"Self-hosted Bitwarden server, whose API is at /api and identity server at /identity"`
	APIURL      string `name:"api-url" help:"API server, with the identity server, such as https://api.bitwarden.eu"`
	IdentityURL string `name:"identity-url" help:"Identity server, with the API server, such as https://identity.bitwarden.eu"`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - ENV

// WithEnvCredentialProvider creates a provider which only reads environment
// variables, and calls fn with it
func WithEnvCredentialProvider(ctx server.Cmd, fn func(provider.CredentialProvider) error) error {
	return fn(envcredential.New(envcredential.WithTracer(ctx.Tracer())))
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - FILE

// WithFileCredentialManager creates the file backend in the directory at the
// path, which is created with permissions 0700 and must be writable,
// without the environment as a fallback, and calls fn with it
func (flags FileFlags) WithFileCredentialManager(ctx server.Cmd, path string, fn func(provider.CredentialManager) error) error {
	mgr, err := filecredential.New(path, flags.options(ctx)...)
	if err != nil {
		return err
	}
	return fn(mgr)
}

// WithFileCredentialProvider creates the file backend in the directory at
// the path, which is created with permissions 0700 and must be writable,
// with the environment as a fallback when env is true, and calls fn with it
func (flags FileFlags) WithFileCredentialProvider(ctx server.Cmd, path string, env bool, fn func(provider.CredentialProvider) error) error {
	opts := flags.options(ctx)
	if env {
		opts = append(opts, filecredential.WithEnv())
	}
	mgr, err := filecredential.New(path, opts...)
	if err != nil {
		return err
	}
	return fn(mgr)
}

func (flags FileFlags) options(ctx server.Cmd) []filecredential.Opt {
	opts := []filecredential.Opt{filecredential.WithTracer(ctx.Tracer())}
	for i, passphrase := range flags.Passphrase {
		opts = append(opts, filecredential.WithPassphrase(uint64(i+1), passphrase))
	}
	return opts
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - PG

// WithPGCredentialManager creates the pg backend in the pool and schema,
// which is the default when it's empty, without the environment as a
// fallback, and calls fn with it. It needs a passphrase.
func (flags PGFlags) WithPGCredentialManager(ctx server.Cmd, pool pg.PoolConn, schema string, fn func(provider.CredentialManager) error) error {
	mgr, err := pgcredential.New(ctx.Context(), pool, flags.options(ctx, schema)...)
	if err != nil {
		return err
	}
	credentials, ok := mgr.GetCredentialProvider().(provider.CredentialManager)
	if !ok {
		return auth.ErrBadParameter.With("pg credentials need a passphrase")
	}
	return fn(credentials)
}

// WithPGCredentialProvider creates the pg backend in the pool and schema,
// which is the default when it's empty, with the environment as a fallback
// when env is true, and calls fn with it. Without a passphrase, credentials
// are only from the environment, or there are none without env.
func (flags PGFlags) WithPGCredentialProvider(ctx server.Cmd, pool pg.PoolConn, schema string, env bool, fn func(provider.CredentialProvider) error) error {
	opts := flags.options(ctx, schema)
	if env {
		opts = append(opts, pgcredential.WithEnv())
	}
	mgr, err := pgcredential.New(ctx.Context(), pool, opts...)
	if err != nil {
		return err
	}
	return fn(mgr.GetCredentialProvider())
}

func (flags PGFlags) options(ctx server.Cmd, schema string) []pgcredential.Opt {
	opts := []pgcredential.Opt{pgcredential.WithTracer(ctx.Tracer())}
	if schema := strings.TrimSpace(schema); schema != "" {
		opts = append(opts, pgcredential.WithSchema(schema))
	}
	for i, passphrase := range flags.Passphrase {
		opts = append(opts, pgcredential.WithPassphrase(uint64(i+1), passphrase))
	}
	return opts
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - AWS

// WithAWSCredentialManager creates the aws backend, without the environment
// as a fallback, and calls fn with it
func (flags AWSFlags) WithAWSCredentialManager(ctx server.Cmd, fn func(provider.CredentialManager) error) error {
	mgr, err := awscredential.New(ctx.Context(), flags.options(ctx)...)
	if err != nil {
		return err
	}
	return fn(mgr)
}

// WithAWSCredentialProvider creates the aws backend, with the environment
// as a fallback when env is true, and calls fn with it
func (flags AWSFlags) WithAWSCredentialProvider(ctx server.Cmd, env bool, fn func(provider.CredentialProvider) error) error {
	opts := flags.options(ctx)
	if env {
		opts = append(opts, awscredential.WithEnv())
	}
	mgr, err := awscredential.New(ctx.Context(), opts...)
	if err != nil {
		return err
	}
	return fn(mgr)
}

func (flags AWSFlags) options(ctx server.Cmd) []awscredential.Opt {
	opts := []awscredential.Opt{awscredential.WithTracer(ctx.Tracer())}
	if flags.Region != "" {
		opts = append(opts, awscredential.WithRegion(flags.Region))
	}
	if flags.Profile != "" {
		opts = append(opts, awscredential.WithProfile(flags.Profile))
	}
	if flags.Endpoint != "" {
		opts = append(opts, awscredential.WithEndpoint(flags.Endpoint))
	}
	if flags.Prefix != "" {
		opts = append(opts, awscredential.WithPrefix(flags.Prefix))
	}
	if flags.KMSKey != "" {
		opts = append(opts, awscredential.WithKMSKey(flags.KMSKey))
	}
	if flags.RecoveryWindow != nil {
		opts = append(opts, awscredential.WithRecoveryWindow(*flags.RecoveryWindow))
	}
	return opts
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - BITWARDEN

// WithBitwardenCredentialManager creates the bitwarden backend, without the
// environment as a fallback, and calls fn with it. New secrets are created
// in the project, by its identifier, which is required, as machine accounts
// can only create secrets in a project they can write to.
func (flags BitwardenFlags) WithBitwardenCredentialManager(ctx server.Cmd, project string, fn func(provider.CredentialManager) error) error {
	if project == "" {
		return auth.ErrBadParameter.With("a bitwarden project is required for new secrets")
	}
	mgr, err := bitwarden.New(append(flags.options(ctx), bitwarden.WithProject(project))...)
	if err != nil {
		return err
	}
	return fn(mgr)
}

// WithBitwardenCredentialProvider creates the bitwarden backend, with the
// environment as a fallback when env is true, and calls fn with it
func (flags BitwardenFlags) WithBitwardenCredentialProvider(ctx server.Cmd, env bool, fn func(provider.CredentialProvider) error) error {
	opts := flags.options(ctx)
	if env {
		opts = append(opts, bitwarden.WithEnv())
	}
	mgr, err := bitwarden.New(opts...)
	if err != nil {
		return err
	}
	return fn(mgr)
}

func (flags BitwardenFlags) options(ctx server.Cmd) []bitwarden.Opt {
	opts := []bitwarden.Opt{bitwarden.WithTracer(ctx.Tracer())}
	if flags.AccessToken != "" {
		opts = append(opts, bitwarden.WithAccessToken(flags.AccessToken))
	}
	if flags.ServerURL != "" {
		opts = append(opts, bitwarden.WithServerURL(flags.ServerURL))
	}
	if flags.APIURL != "" || flags.IdentityURL != "" {
		opts = append(opts, bitwarden.WithURLs(flags.APIURL, flags.IdentityURL))
	}
	return opts
}
