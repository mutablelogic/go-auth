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

//go:build !client && aws

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

// BackendFlags stores credentials in AWS Secrets Manager. The region and
// credentials are from the AWS environment variables and configuration,
// unless they're flags.
type BackendFlags struct {
	credentialcmd.AWSFlags
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	backend = "aws"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (flags BackendFlags) withManager(ctx server.Cmd, _ pg.PoolConn, _ *follow, _ []string, fn func(credential.CredentialManager, bool) error) error {
	return flags.WithAWSCredentialManager(ctx, unnotified(fn))
}
