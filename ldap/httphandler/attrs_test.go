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
	"testing"

	// Packages
	assert "github.com/stretchr/testify/assert"
)

func Test_attrsSchema(t *testing.T) {
	// A value is a string, or {"base64": "..."}, in objects, lists, password
	// responses and requests
	assert.NoError(t, objectSchema.Validate([]byte(`{"dn":"cn=a","attrs":{"cn":["a"],"objectGUID":[{"base64":"AQI="}]}}`)))
	assert.NoError(t, listSchema.Validate([]byte(`{"count":1,"body":[{"dn":"cn=a","attrs":{"jpegPhoto":[{"base64":"AQI="}]}}]}`)))
	assert.NoError(t, passwordSchema.Validate([]byte(`{"dn":"cn=a","attrs":{"cn":["a"]},"generated-password":"x"}`)))
	assert.NoError(t, putSchema.Validate([]byte(`{"attrs":{"userCertificate;binary":[{"base64":"AQI="}]}}`)))
	assert.NoError(t, putSchema.Validate([]byte(`{}`)), "no attributes")

	// Not anything else
	assert.Error(t, objectSchema.Validate([]byte(`{"dn":"cn=a","attrs":{"cn":[1]}}`)))
	assert.Error(t, objectSchema.Validate([]byte(`{"dn":"cn=a","attrs":{"cn":[{"hex":"01"}]}}`)))
	assert.Error(t, putSchema.Validate([]byte(`{"attrs":{"cn":"a"}}`)))
}
