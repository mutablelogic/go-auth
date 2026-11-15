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
	"errors"
	"fmt"
	"os"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	httpclient "github.com/mutablelogic/go-auth/credential/httpclient"
	server "github.com/mutablelogic/go-server"
	tui "github.com/mutablelogic/go-server/pkg/tui"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// CredentialManagerCommands list, delete and rotate stored credentials
type CredentialManagerCommands struct {
	CredentialList   CredentialListCmd   `cmd:"" name:"credentials" help:"List credential keys." group:"CREDENTIAL"`
	CredentialDelete CredentialDeleteCmd `cmd:"" name:"credential-delete" help:"Delete a credential by key." group:"CREDENTIAL"`
	CredentialRotate CredentialRotateCmd `cmd:"" name:"credential-rotate" help:"Re-encrypt a credential, or with --all every one which needs it, with the latest passphrase version." group:"CREDENTIAL"`
}

type CredentialListCmd struct{}

type CredentialDeleteCmd struct {
	Key string `arg:"" name:"key" help:"Credential key (identifier)."`
}

type CredentialRotateCmd struct {
	All bool   `name:"all" help:"Rotate every credential which needs rotating, rather than one."`
	Key string `arg:"" optional:"" name:"key" help:"Credential key (identifier)."`
}

// credentialRow is a row of the credentials table
type credentialRow credential.Credential

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (cmd *CredentialListCmd) Run(ctx server.Cmd) error {
	width, debug := ctx.IsTerm(), ctx.IsDebug()
	return withClient(ctx, "credential.CredentialListCmd", func(ctx context.Context, client *httpclient.Client) error {
		list, err := client.ListCredentials(ctx)
		if err != nil {
			return err
		}

		// With debugging, print the response
		if debug {
			fmt.Println(list)
			return nil
		}

		// Credentials table and summary
		rows := make([]credentialRow, 0, len(list.Body))
		for _, c := range list.Body {
			rows = append(rows, credentialRow(c))
		}
		if _, err := tui.TableFor[credentialRow](tui.SetWidth(width)).Write(os.Stdout, rows...); err != nil {
			return err
		}
		_, err = tui.TableSummary("credentials", uint(list.Count), uint(len(list.Body)), 0, nil).Write(os.Stdout)
		return err
	})
}

func (cmd *CredentialDeleteCmd) Run(ctx server.Cmd) error {
	return withClient(ctx, "credential.CredentialDeleteCmd", func(ctx context.Context, client *httpclient.Client) error {
		if err := client.DeleteCredential(ctx, cmd.Key); err != nil {
			return err
		}
		fmt.Println("deleted credential", cmd.Key)
		return nil
	})
}

func (cmd *CredentialRotateCmd) Run(ctx server.Cmd) error {
	if cmd.All == (cmd.Key != "") {
		return fmt.Errorf("either a key, or --all, is required")
	}
	return withClient(ctx, "credential.CredentialRotateCmd", func(ctx context.Context, client *httpclient.Client) error {
		if !cmd.All {
			return rotate(ctx, client, cmd.Key)
		}

		// Rotate each credential which needs rotating
		list, err := client.ListCredentials(ctx)
		if err != nil {
			return err
		}
		rotated := 0
		for _, c := range list.Body {
			if !c.Rotate {
				continue
			} else if err := rotate(ctx, client, c.Key); err != nil {
				return err
			}
			rotated++
		}
		fmt.Printf("rotated %d credentials\n", rotated)
		return nil
	})
}

// rotate rotates the credential, which isn't an error when it already uses
// the latest passphrase version
func rotate(ctx context.Context, client *httpclient.Client, key string) error {
	if err := client.RotateCredential(ctx, key); errors.Is(err, auth.ErrNotModified) {
		fmt.Fprintf(os.Stderr, "credential %q already uses the latest passphrase version\n", key)
		return nil
	} else if err != nil {
		return err
	}
	fmt.Println("rotated credential", key)
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// TABLE

func (r credentialRow) Header() []string {
	return []string{"Key", "Description", "Updated", "Rotate"}
}

func (r credentialRow) Width(int) int {
	return 0
}

func (r credentialRow) Cell(col int) tui.CellText {
	switch col {
	case 0:
		return r.Key
	case 1:
		return r.Description
	case 2:
		if r.UpdatedAt.IsZero() {
			return ""
		}
		return r.UpdatedAt.Local().Format(time.DateTime)
	case 3:
		if r.Rotate {
			return "needed"
		}
		return ""
	default:
		return ""
	}
}
