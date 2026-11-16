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

package schema

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"unicode/utf8"

	// Packages
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

//////////////////////////////////////////////////////////////////////////////////
// TYPES

// Attrs are the attributes of an object, and their values. In JSON, a value
// is a string, or, when it isn't UTF-8, such as a certificate, an object
// with its bytes in base64: {"base64": "..."}
type Attrs url.Values

type binaryValue struct {
	Base64 string `json:"base64"`
}

//////////////////////////////////////////////////////////////////////////////////
// GLOBALS

// attrsSchema is the schema of Attrs' JSON: an object of attributes, each a
// list of values, which are strings, or {"base64": "..."}. It's null when
// there are none, and a list is null in an update, which deletes it.
var attrsSchema = must(jsonschema.FromJSON(json.RawMessage(`{
	"type": ["object", "null"],
	"additionalProperties": {
		"type": ["array", "null"],
		"items": {
			"anyOf": [
				{"type": "string"},
				{
					"type": "object",
					"description": "A value which isn't UTF-8",
					"properties": {"base64": {"type": "string", "contentEncoding": "base64"}},
					"required": ["base64"],
					"additionalProperties": false
				}
			]
		}
	}
}`)))

///////////////////////////////////////////////////////////////////////////////
// JSON SCHEMA

// JSONSchema returns the schema of the attributes' JSON, whose values are
// strings, or {"base64": "..."}, as MarshalJSON writes them, rather than
// strings, as the type says
func (Attrs) JSONSchema() *jsonschema.Schema {
	return attrsSchema
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

///////////////////////////////////////////////////////////////////////////////
// JSON

func (a Attrs) MarshalJSON() ([]byte, error) {
	if a == nil {
		return []byte("null"), nil
	}
	result := make(map[string][]any, len(a))
	for key, values := range a {
		encoded := make([]any, 0, len(values))
		for _, value := range values {
			if utf8.ValidString(value) {
				encoded = append(encoded, value)
			} else {
				encoded = append(encoded, binaryValue{Base64: base64.StdEncoding.EncodeToString([]byte(value))})
			}
		}
		result[key] = encoded
	}
	return json.Marshal(result)
}

func (a *Attrs) UnmarshalJSON(data []byte) error {
	var raw map[string][]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		*a = nil
		return nil
	}
	result := make(Attrs, len(raw))
	for key, values := range raw {
		decoded := make([]string, 0, len(values))
		for _, value := range values {
			if bytes.HasPrefix(bytes.TrimSpace(value), []byte("{")) {
				var binary binaryValue
				if err := json.Unmarshal(value, &binary); err != nil {
					return err
				}
				data, err := base64.StdEncoding.DecodeString(binary.Base64)
				if err != nil {
					return err
				}
				decoded = append(decoded, string(data))
			} else {
				var text string
				if err := json.Unmarshal(value, &text); err != nil {
					return err
				}
				decoded = append(decoded, text)
			}
		}
		result[key] = decoded
	}
	*a = result
	return nil
}
