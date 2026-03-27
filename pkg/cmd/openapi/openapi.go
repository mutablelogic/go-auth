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

package openapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	// Packages
	authclient "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
	browser "github.com/pkg/browser"
	yaml "gopkg.in/yaml.v3"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type OpenAPICommands struct {
	OpenAPI OpenAPICommand `cmd:"" name:"openapi" help:"Show OpenAPI documentation in a browser, or output the spec as JSON or YAML." group:"SERVER"`
}

type OpenAPICommand struct {
	JSON bool `name:"json" xor:"format" help:"Output OpenAPI spec as JSON."`
	YAML bool `name:"yaml" xor:"format" help:"Output OpenAPI spec as YAML."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *OpenAPICommand) Run(ctx server.Cmd) error {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}

	if !cmd.JSON && !cmd.YAML {
		u, err := url.JoinPath(endpoint, "openapi.html")
		if err != nil {
			return err
		}
		return browser.OpenURL(u)
	}

	c, err := authclient.New(endpoint, opts...)
	if err != nil {
		return err
	}

	var spec map[string]any
	if err := c.DoWithContext(ctx.Context(), nil, &spec, client.OptPath("openapi.json")); err != nil {
		return err
	}

	if cmd.JSON {
		data, err := json.MarshalIndent(spec, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, string(data))
		return err
	}

	// YAML
	data, err := yaml.Marshal(spec)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(os.Stdout, string(data))
	return err
}
