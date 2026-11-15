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

//go:build !client && !pg && !aws && !bitwarden

package main

import (
	"os"
	"path/filepath"

	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
	credentialcmd "github.com/mutablelogic/go-auth/credential/cmd"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// BackendFlags stores credentials in encrypted files, in a directory in the
// user's configuration directory, unless --credential.path is set
type BackendFlags struct {
	credentialcmd.FileFlags
	Path string `name:"path" env:"CREDENTIAL_PATH" help:"Directory for credential files, created with permissions 0700. Defaults to a directory in the user's configuration directory."`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	backend = "file"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (flags BackendFlags) withManager(ctx server.Cmd, fn func(credential.CredentialManager) error) error {
	path := flags.Path
	if path == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		path = filepath.Join(config, ctx.Name(), "credential")
	}
	if len(flags.Passphrase) == 0 {
		ctx.Logger().WarnContext(ctx.Context(), "No passphrase, so credentials can't be stored or read: set --credential.passphrase")
	}
	ctx.Logger().InfoContext(ctx.Context(), "Credential files", "path", path)
	return flags.WithFileCredentialManager(ctx, path, fn)
}
