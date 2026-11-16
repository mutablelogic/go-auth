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

package httphandler

import (
	"encoding/json"

	// Packages
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// The schemas of requests and responses which have attributes, whose values
// are strings, or, when they aren't UTF-8, {"base64": "..."}
var (
	objectSchema   = attrsSchema(jsonschema.MustFor[schema.Object]())
	listSchema     = attrsSchema(jsonschema.MustFor[schema.ObjectList]())
	passwordSchema = attrsSchema(jsonschema.MustFor[schema.PasswordResponse]())
	putSchema      = attrsSchema(jsonschema.MustFor[schema.ObjectPutRequest]())
)

// valueSchema is the schema of an attribute's value
var valueSchema = map[string]any{
	"anyOf": []any{
		map[string]any{"type": "string"},
		map[string]any{
			"type":                 "object",
			"description":          "A value which isn't UTF-8",
			"properties":           map[string]any{"base64": map[string]any{"type": "string", "contentEncoding": "base64"}},
			"required":             []any{"base64"},
			"additionalProperties": false,
		},
	},
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// attrsSchema returns the schema, with the values of each attrs property's
// attributes as a string, or {"base64": "..."}, as schema.Attrs has them
func attrsSchema(s *jsonschema.Schema) *jsonschema.Schema {
	data, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	var tree any
	if err := json.Unmarshal(data, &tree); err != nil {
		panic(err)
	}
	replaceAttrValues(tree)
	if data, err = json.Marshal(tree); err != nil {
		panic(err)
	}
	result, err := jsonschema.FromJSON(data)
	if err != nil {
		panic(err)
	}
	return result
}

// replaceAttrValues replaces the items of each attrs property's attributes
func replaceAttrValues(node any) {
	switch node := node.(type) {
	case map[string]any:
		if properties, ok := node["properties"].(map[string]any); ok {
			if attrs, ok := properties["attrs"].(map[string]any); ok {
				if values, ok := attrs["additionalProperties"].(map[string]any); ok {
					values["items"] = valueSchema
				}
			}
		}
		for _, child := range node {
			replaceAttrValues(child)
		}
	case []any:
		for _, child := range node {
			replaceAttrValues(child)
		}
	}
}
