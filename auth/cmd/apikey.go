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
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	// Packages
	authpkg "github.com/mutablelogic/go-auth"
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	server "github.com/mutablelogic/go-server"
	tui "github.com/mutablelogic/go-server/pkg/tui"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type KeyCommands struct {
	Keys      ListKeysCommand  `cmd:"" name:"keys" help:"Get API keys." group:"AUTH MANAGER"`
	Key       GetKeyCommand    `cmd:"" name:"key" help:"Get API key." group:"AUTH MANAGER"`
	CreateKey CreateKeyCommand `cmd:"" name:"key-create" help:"Create API key." group:"AUTH MANAGER"`
	UpdateKey UpdateKeyCommand `cmd:"" name:"key-update" help:"Update API key." group:"AUTH MANAGER"`
	DeleteKey DeleteKeyCommand `cmd:"" name:"key-delete" help:"Delete API key." group:"AUTH MANAGER"`
}

type ListKeysCommand struct {
	schema.KeyListRequest
}

type GetKeyCommand struct {
	ID schema.KeyID `arg:"" name:"key" help:"API key UUID"`
}

type CreateKeyCommand struct {
	schema.KeyMeta
}

type UpdateKeyCommand struct {
	GetKeyCommand
	schema.KeyMeta
	NoExpiresAt bool `name:"no-expires-at" help:"Remove the key expiry instead of setting one."`
}

type DeleteKeyCommand struct {
	GetKeyCommand
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListKeysCommand) Run(globals server.Cmd) error {
	return withManager(globals, "ListKeysCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		keys, err := client.ListKeys(ctx, cmd.KeyListRequest)
		if err != nil {
			return err
		}

		keyRows := make([]keyRow, len(keys.Body))
		for i, key := range keys.Body {
			keyRows[i] = keyRow(key)
		}

		tui.TableFor[keyRow](tui.SetWidth(globals.IsTerm())).Write(os.Stdout, keyRows...)
		tui.TableSummary("keys", keys.Count, keys.Offset, keys.Limit).Write(os.Stdout)

		return nil
	})
}

func (cmd *GetKeyCommand) Run(globals server.Cmd) error {
	return withManager(globals, "GetKeyCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		key, err := client.GetKey(ctx, cmd.ID)
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// TABLE OUTPUT

type keyRow schema.Key

func (r keyRow) Header() []string {
	return []string{"Name", "UUID", "Expires", "Status"}
}

func (r keyRow) Cell(i int) string {
	switch i {
	case 0:
		return r.Name
	case 1:
		return r.ID.String()
	case 2:
		if r.ExpiresAt == nil {
			return ""
		}
		return r.ExpiresAt.Format("2006-01-02 15:04:05Z07:00")
	case 3:
		return string(types.Value(r.Status))
	default:
		return ""
	}
}

func (r keyRow) Width(i int) int {
	switch i {
	case 0:
		return 0
	case 1:
		return 0
	case 2:
		return 0
	case 3:
		return len(strings.TrimSpace(string(types.Value(r.Status))))
	default:
		return 0
	}
}

func (cmd *CreateKeyCommand) Run(globals server.Cmd) error {
	return withManager(globals, "CreateKeyCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		key, err := client.CreateKey(ctx, cmd.KeyMeta)
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	})
}

func (cmd *UpdateKeyCommand) Run(globals server.Cmd) error {
	return withManager(globals, "UpdateKeyCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		if cmd.NoExpiresAt {
			if cmd.ExpiresAt != nil {
				return authpkg.ErrBadParameter.With("cannot use --no-expires-at with --expires-at")
			} else {
				cmd.ExpiresAt = types.Ptr(time.Time{})
			}
		}

		key, err := client.UpdateKey(ctx, cmd.ID, cmd.KeyMeta)
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	})
}

func (cmd *DeleteKeyCommand) Run(globals server.Cmd) error {
	return withManager(globals, "DeleteKeyCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		if err := client.DeleteKey(ctx, cmd.ID); err != nil {
			return err
		}
		return nil
	})
}
