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

package env_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	env "github.com/mutablelogic/go-auth/credential/env"
	assert "github.com/stretchr/testify/assert"
)

func Test_Get(t *testing.T) {
	assert := assert.New(t)
	provider := env.New()
	t.Setenv("GOAUTH_TEST_STRING", "secret value")
	t.Setenv("GOAUTH_TEST_JSON", `{"token":"abc"}`)
	t.Setenv("GOAUTH_TEST_EMPTY", "")

	value, err := provider.Get(context.Background(), "GOAUTH_TEST_STRING")
	assert.NoError(err)
	assert.Equal(json.RawMessage(`"secret value"`), value)

	value, err = provider.Get(context.Background(), "GOAUTH_TEST_JSON")
	assert.NoError(err)
	assert.Equal(json.RawMessage(`{"token":"abc"}`), value)

	value, err = provider.Get(context.Background(), "GOAUTH_TEST_EMPTY")
	assert.NoError(err)
	assert.Equal(json.RawMessage(`""`), value)

	_, err = provider.Get(context.Background(), "GOAUTH_TEST_MISSING")
	assert.ErrorIs(err, auth.ErrNotFound)

	_, err = provider.Get(context.Background(), "")
	assert.ErrorIs(err, auth.ErrBadParameter)
}

func Test_Expand(t *testing.T) {
	assert := assert.New(t)
	provider := env.New()
	t.Setenv("GOAUTH_TEST_USER", "ops")
	t.Setenv("GOAUTH_TEST_PASS", "secret")

	value, err := provider.Expand(context.Background(), "$GOAUTH_TEST_USER:${GOAUTH_TEST_PASS}@host")
	assert.NoError(err)
	assert.Equal("ops:secret@host", value)

	value, err = provider.Expand(context.Background(), "no placeholders")
	assert.NoError(err)
	assert.Equal("no placeholders", value)

	_, err = provider.Expand(context.Background(), "$GOAUTH_TEST_USER:$GOAUTH_TEST_A ${GOAUTH_TEST_B} $GOAUTH_TEST_A")
	assert.ErrorIs(err, auth.ErrNotFound)
	assert.Contains(err.Error(), "GOAUTH_TEST_A")
	assert.Contains(err.Error(), "GOAUTH_TEST_B")
}

func Test_Set(t *testing.T) {
	err := env.New().Set(context.Background(), "GOAUTH_TEST_STRING", json.RawMessage(`"value"`))
	assert.True(t, errors.Is(err, auth.ErrNotImplemented))
}

func Test_Delete(t *testing.T) {
	t.Setenv("GOAUTH_TEST_STRING", "value")
	err := env.New().Delete(context.Background(), "GOAUTH_TEST_STRING")
	assert.True(t, errors.Is(err, auth.ErrNotImplemented))
	assert.Equal(t, "value", os.Getenv("GOAUTH_TEST_STRING"), "the environment isn't changed")
}
