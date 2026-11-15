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

//go:build !client && bitwarden

package main

import (
	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
	credentialcmd "github.com/mutablelogic/go-auth/credential/cmd"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// BackendFlags stores credentials in Bitwarden Secrets Manager, for a
// machine account, creating new secrets in the project
type BackendFlags struct {
	credentialcmd.BitwardenFlags
	Project string `name:"project" env:"BWS_PROJECT" help:"Project for new secrets, by its identifier, which the machine account can write to"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	backend = "bitwarden"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (flags BackendFlags) withManager(ctx server.Cmd, _ pg.PoolConn, _ *follow, _ []string, fn func(credential.CredentialManager, bool) error) error {
	return flags.WithBitwardenCredentialManager(ctx, flags.Project, unnotified(fn))
}
