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

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	// Packages
	authcmd "github.com/mutablelogic/go-auth/auth/cmd"
	cert "github.com/mutablelogic/go-auth/cert/cmd"
	credential "github.com/mutablelogic/go-auth/credential/cmd"
	ldap "github.com/mutablelogic/go-auth/ldap/cmd"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	version "github.com/mutablelogic/go-server/pkg/version"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// CLI has the credential, certificate and LDAP client commands, and the
// server commands, unless it's built with the client tag
type CLI struct {
	authcmd.AuthCommands
	credential.CredentialProviderCommands
	credential.CredentialManagerCommands
	cert.CertCommands
	cert.SubjectCommands
	ldap.ObjectCommands
	ldap.UserCommands
	ldap.GroupCommands
	ldap.SchemaCommands
	ServerCommands
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func main() {
	if err := cmd.Main(CLI{}, "Credential, certificate and LDAP server and client", version.Version()); err != nil {
		str, code := formatError(err)
		fmt.Fprintln(os.Stderr, "Error:", str)
		os.Exit(code)
	}
}

// formatError returns the reason of an error response, and its status code,
// or the error and -1
func formatError(err error) (string, int) {
	var response httpresponse.ErrResponse
	if errors.As(err, &response) {
		reason := strings.TrimSpace(response.Reason)
		if response.Code == http.StatusUnauthorized {
			// Signing in is how a request is authorized
			reason = strings.TrimSuffix(reason, ".") + ": sign in with " + filepath.Base(os.Args[0]) + " login"
		}
		if reason != "" {
			return reason, response.Code
		}
	}
	return err.Error(), -1
}
