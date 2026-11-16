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
	"strings"
	"testing"
	"time"

	// Packages
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_sealer(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	s, err := newSealer(key)
	require.NoError(t, err)
	now := time.Now()
	in := signin{Provider: "google", State: "state", Verifier: "verifier", Expires: now.Add(time.Minute).Unix()}
	value, err := s.seal(in)
	require.NoError(t, err)
	assert.NotContains(t, value, "verifier", "it can't be read")

	// It opens, for its provider, until it expires
	out, err := s.open(value, "google", now)
	require.NoError(t, err)
	assert.Equal(t, in, *out)
	_, err = s.open(value, "github", now)
	assert.ErrorIs(t, err, errCookie, "another provider's")
	_, err = s.open(value, "google", now.Add(2*time.Minute))
	assert.ErrorIs(t, err, errCookie, "expired")

	// Not with another key, nor changed
	other, err := newSealer([]byte(strings.Repeat("x", 32)))
	require.NoError(t, err)
	_, err = other.open(value, "google", now)
	assert.ErrorIs(t, err, errCookie)
	_, err = s.open(flip(value, len(value)-1), "google", now)
	assert.ErrorIs(t, err, errCookie)
	_, err = s.open(flip(value, 0), "google", now)
	assert.ErrorIs(t, err, errCookie, "its nonce")
	_, err = s.open("not base64!", "google", now)
	assert.ErrorIs(t, err, errCookie)

	// Each seal is different, with its own nonce
	again, err := s.seal(in)
	require.NoError(t, err)
	assert.NotEqual(t, value, again)
}

// flip returns the value, with the character at i another, which is always
// different, and is base64url
func flip(value string, i int) string {
	c := byte('A')
	if value[i] == 'A' {
		c = 'B'
	}
	return value[:i] + string(c) + value[i+1:]
}
