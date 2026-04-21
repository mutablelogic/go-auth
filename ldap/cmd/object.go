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

package ldap

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	// Packages
	ldap "github.com/mutablelogic/go-auth/ldap/httpclient"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	server "github.com/mutablelogic/go-server"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	term "golang.org/x/term"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ObjectCommands struct {
	Objects ListObjectsCommand    `cmd:"" name:"objects" help:"List Objects." group:"LDAP OBJECTS"`
	Object  GetObjectCommand      `cmd:"" name:"object" help:"Get Object." group:"LDAP OBJECTS"`
	Create  CreateObjectCommand   `cmd:"" name:"object-create" help:"Create Object." group:"LDAP OBJECTS"`
	Update  UpdateObjectCommand   `cmd:"" name:"object-update" help:"Update Object." group:"LDAP OBJECTS"`
	Delete  DeleteObjectCommand   `cmd:"" name:"object-delete" help:"Delete Object." group:"LDAP OBJECTS"`
	Bind    BindObjectCommand     `cmd:"" name:"object-bind" help:"Bind Object." group:"LDAP OBJECTS"`
	Passwd  PasswordObjectCommand `cmd:"" name:"object-password" help:"Change Object Password." group:"LDAP OBJECTS"`
}

type ListObjectsCommand struct {
	schema.ObjectListRequest
}

type GetObjectCommand struct {
	DN string `arg:"" name:"dn" help:"Object distinguished name"`
}

type CreateObjectCommand struct {
	DN    string   `arg:"" name:"dn" help:"Object distinguished name"`
	Attrs []string `arg:"" name:"attrs" help:"Attributes as key=value1,value2"`
}

type UpdateObjectCommand struct {
	DN    string   `arg:"" name:"dn" help:"Object distinguished name"`
	Attrs []string `arg:"" name:"attrs" help:"Attributes as key=value1,value2"`
}

type DeleteObjectCommand struct {
	GetObjectCommand
}

type BindObjectCommand struct {
	DN       string `arg:"" name:"dn" help:"Object distinguished name"`
	Password string `arg:"" optional:"" name:"password" help:"Object password. Omit to be prompted"`
}

type PasswordObjectCommand struct {
	DN  string `arg:"" name:"dn" help:"Object distinguished name"`
	Old string `arg:"" optional:"" name:"old" help:"Current password. Leave empty to treat the object as having no password"`
	New string `arg:"" optional:"" name:"new" help:"New password. If omitted, you will be prompted and an empty entry requests a generated password"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListObjectsCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		objects, err := manager.ListObjects(ctx.Context(), cmd.ObjectListRequest)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(objects)
		} else {
			fmt.Println(objects.LDIF())
		}
		return nil
	})
}

func (cmd *GetObjectCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		object, err := manager.GetObject(ctx.Context(), cmd.DN)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(object)
		} else {
			fmt.Println(object.LDIF())
		}
		return nil
	})
}

func (cmd *CreateObjectCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		attrs, err := objectAttrs(cmd.Attrs)
		if err != nil {
			return err
		}
		object, err := manager.CreateObject(ctx.Context(), cmd.DN, schema.ObjectPutRequest{Attrs: attrs})
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(object)
		} else {
			fmt.Println(object.LDIF())
		}
		return nil
	})
}

func (cmd *UpdateObjectCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		attrs, err := objectAttrs(cmd.Attrs)
		if err != nil {
			return err
		}
		object, err := manager.UpdateObject(ctx.Context(), cmd.DN, schema.ObjectPutRequest{Attrs: attrs})
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(object)
		} else {
			fmt.Println(object.LDIF())
		}
		return nil
	})
}

func (cmd *DeleteObjectCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		object, err := manager.DeleteObject(ctx.Context(), cmd.DN)
		if err != nil {
			return err
		}
		printDeletedObject(ctx, object)
		return nil
	})
}

func (cmd *BindObjectCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		password, err := promptPasswordIfMissing("Password: ", cmd.Password)
		if err != nil {
			return err
		}
		object, err := manager.BindObject(ctx.Context(), cmd.DN, password)
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(object)
		} else {
			fmt.Println(object.LDIF())
		}
		return nil
	})
}

func (cmd *PasswordObjectCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *ldap.Client, endpoint string) error {
		oldPassword := strings.TrimSpace(cmd.Old)
		newPassword, err := promptPasswordWithConfirmationOrGenerate("New password: ", "Confirm new password: ", cmd.New)
		if err != nil {
			return err
		}
		response, err := manager.ChangeObjectPassword(ctx.Context(), cmd.DN, schema.ObjectPasswordRequest{
			Old: oldPassword,
			New: newPassword,
		})
		if err != nil {
			return err
		}
		if ctx.IsDebug() {
			fmt.Println(response)
		} else {
			fmt.Println(response.LDIF())
		}
		return nil
	})
}

func objectAttrs(values []string) (url.Values, error) {
	attrs := make(url.Values)
	for _, value := range values {
		key, raw, ok := strings.Cut(value, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, httpresponse.ErrBadRequest.Withf("invalid attribute %q, expected key=value", value)
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "null") {
			attrs[key] = nil
			continue
		}
		parts := strings.Split(raw, ",")
		for _, part := range parts {
			attrs.Add(key, strings.TrimSpace(part))
		}
	}
	return attrs, nil
}

func printDeletedObject(ctx server.Cmd, object *schema.Object) {
	if ctx.IsDebug() {
		fmt.Println("# deleted object")
		fmt.Println(object)
		return
	}
	fmt.Println("# deleted object")
	fmt.Println(object.LDIF())
}

func promptPasswordIfMissing(prompt, value string) (string, error) {
	if strings.TrimSpace(value) != "" {
		return value, nil
	}
	password, err := promptPassword(prompt)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(password) == "" {
		return "", httpresponse.ErrBadRequest.With("password cannot be empty")
	}
	return password, nil
}

func promptPasswordWithConfirmationOrGenerate(prompt, confirm, value string) (*string, error) {
	if strings.TrimSpace(value) != "" {
		return &value, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, nil
	}
	password, err := promptPassword(prompt)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(password) == "" {
		return nil, nil
	}
	confirmed, err := promptPassword(confirm)
	if err != nil {
		return nil, err
	}
	if password != confirmed {
		return nil, httpresponse.ErrBadRequest.With("passwords do not match")
	}
	return &password, nil
}

func promptPassword(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", httpresponse.ErrBadRequest.With("password is required when stdin is not a terminal")
	}
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", err
	}
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if _, writeErr := fmt.Fprintln(os.Stderr); err == nil && writeErr != nil {
		err = writeErr
	}
	if err != nil {
		return "", err
	}
	return string(password), nil
}
