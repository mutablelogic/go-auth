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

package schema_test

import (
	"encoding/json"
	"testing"

	// Packages
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	assert "github.com/stretchr/testify/assert"
)

func Test_AttrsSchema(t *testing.T) {
	// A value is a string, or {"base64": "..."}, as Attrs writes it, in
	// objects, lists, password responses and requests
	object := jsonschema.MustFor[schema.Object]()
	assert.NoError(t, object.Validate(json.RawMessage(`{"dn":"cn=a","attrs":{"cn":["a"],"objectGUID":[{"base64":"AQI="}]}}`)))
	assert.NoError(t, jsonschema.MustFor[schema.ObjectList]().Validate(json.RawMessage(`{"count":1,"body":[{"dn":"cn=a","attrs":{"jpegPhoto":[{"base64":"AQI="}]}}]}`)))
	assert.NoError(t, jsonschema.MustFor[schema.PasswordResponse]().Validate(json.RawMessage(`{"dn":"cn=a","attrs":{"cn":["a"]},"generated-password":"x"}`)))
	put := jsonschema.MustFor[schema.ObjectPutRequest]()
	assert.NoError(t, put.Validate(json.RawMessage(`{"attrs":{"userCertificate;binary":[{"base64":"AQI="}]}}`)))
	assert.NoError(t, put.Validate(json.RawMessage(`{}`)), "no attributes")

	// Not anything else
	assert.Error(t, object.Validate(json.RawMessage(`{"dn":"cn=a","attrs":{"cn":[1]}}`)))
	assert.Error(t, object.Validate(json.RawMessage(`{"dn":"cn=a","attrs":{"cn":[{"hex":"01"}]}}`)))
	assert.Error(t, put.Validate(json.RawMessage(`{"attrs":{"cn":"a"}}`)))

	// And the values Attrs writes are valid
	data, err := json.Marshal(schema.Object{DN: "cn=a", Values: schema.Attrs{"cn": {"a"}, "objectGUID": {string([]byte{0xff, 0x00})}}})
	assert.NoError(t, err)
	assert.NoError(t, object.Validate(data))
}
