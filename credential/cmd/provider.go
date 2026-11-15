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

package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	// Packages
	schema "github.com/mutablelogic/go-auth/credential"
	httpclient "github.com/mutablelogic/go-auth/credential/httpclient"
	server "github.com/mutablelogic/go-server"
	term "golang.org/x/term"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// CredentialProviderCommands store credentials, and get a credential's
// value, with the passphrase it was encrypted with
type CredentialProviderCommands struct {
	CredentialGet CredentialGetCmd `cmd:"" name:"credential" help:"Get a credential by key, reading the passphrase from stdin. Prints only to a pipe or file, unless --show is set." group:"CREDENTIAL"`
	CredentialSet CredentialSetCmd `cmd:"" name:"credential-set" help:"Store a credential, replacing any with the key, reading its value from stdin." group:"CREDENTIAL"`
}

type CredentialGetCmd struct {
	Json bool   `name:"json" help:"Output string credentials as JSON strings." negatable:""`
	Show bool   `name:"show" help:"Print the credential when the output is a terminal, rather than a pipe or file."`
	Key  string `arg:"" name:"key" help:"Credential key (identifier)."`
}

type CredentialSetCmd struct {
	Json        bool    `name:"json" help:"Interpret the credential value as JSON, rather than a string." negatable:""`
	Description *string `name:"description" help:"Description of the credential, such as what it's for, which is kept when it isn't set, and removed when it's empty."`
	Key         string  `arg:"" name:"key" help:"Credential key (identifier)."`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (cmd *CredentialGetCmd) Run(ctx server.Cmd) error {
	// Don't print the credential on a terminal, where it would be visible on
	// the screen and in the scrollback, unless asked to. Check this before
	// asking for the passphrase.
	if term.IsTerminal(int(os.Stdout.Fd())) && !cmd.Show {
		return fmt.Errorf("not printing credential %q to a terminal: pipe or redirect the output, or use --show", cmd.Key)
	}

	// Read the passphrase, which is never on the command line, so it isn't
	// in the shell history or the process list
	passphrase, err := readSecret("Passphrase: ")
	if err != nil {
		return err
	} else if len(passphrase) == 0 {
		return fmt.Errorf("passphrase is required")
	}

	return withClient(ctx, "credential.CredentialGetCmd", func(ctx context.Context, client *httpclient.Client) error {
		var credential any
		if err := client.GetCredential(ctx, cmd.Key, string(passphrase), &credential); err != nil {
			return err
		}
		return writeCredential(os.Stdout, credential, cmd.Json)
	})
}

func (cmd *CredentialSetCmd) Run(ctx server.Cmd) error {
	// Read the value, which is never on the command line
	value, err := readSecret("Credential: ")
	if err != nil {
		return err
	} else if len(value) == 0 {
		return fmt.Errorf("credential value is required")
	}

	// The value is a string, unless it's JSON
	var credential json.RawMessage
	if cmd.Json {
		if !json.Valid(value) {
			return fmt.Errorf("credential value is not JSON")
		}
		credential = value
	} else if credential, err = json.Marshal(string(value)); err != nil {
		return err
	}

	return withClient(ctx, "credential.CredentialSetCmd", func(ctx context.Context, client *httpclient.Client) error {
		stored, err := client.SetCredential(ctx, schema.CredentialSet{Key: cmd.Key, Credentials: credential, Description: cmd.Description})
		if err != nil {
			return err
		}
		fmt.Println("stored credential", stored.Key)
		return nil
	})
}
