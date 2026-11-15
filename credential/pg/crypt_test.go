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

package pg

import (
	"encoding/json"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// HELPERS

// newCryptManager returns a manager with the options applied, without a
// database, for testing encryption
func newCryptManager(t *testing.T, opts ...Opt) *Manager {
	t.Helper()
	self := new(Manager)
	if err := self.opt.apply(opts); err != nil {
		t.Fatal(err)
	}
	return self
}

///////////////////////////////////////////////////////////////////////////////
// TESTS - encryptCredentials

func TestEncryptNil(t *testing.T) {
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	pv, data, err := m.encryptCredentials(nil)
	require.NoError(t, err)
	require.Equal(t, uint64(0), pv)
	require.Empty(t, data)
}

func TestEncryptEmptyString(t *testing.T) {
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	pv, data, err := m.encryptCredentials("")
	require.NoError(t, err)
	require.Equal(t, uint64(0), pv)
	require.Empty(t, data)
}

func TestEncryptEmptyBytes(t *testing.T) {
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	pv, data, err := m.encryptCredentials([]byte{})
	require.NoError(t, err)
	require.Equal(t, uint64(0), pv)
	require.Empty(t, data)
}

func TestEncryptEmptyObject(t *testing.T) {
	// A value which encodes as an empty JSON object is not encrypted
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	pv, data, err := m.encryptCredentials(struct{}{})
	require.NoError(t, err)
	require.Equal(t, uint64(0), pv)
	require.Empty(t, data)
}

func TestEncryptNoPassphrase(t *testing.T) {
	m := newCryptManager(t)
	_, _, err := m.encryptCredentials("secret")
	require.ErrorIs(t, err, auth.ErrServiceUnavailable)
}

func TestEncryptInvalidJSON(t *testing.T) {
	// A value which cannot be encoded as JSON is rejected
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	_, _, err := m.encryptCredentials(make(chan int))
	require.ErrorIs(t, err, auth.ErrBadParameter)
}

func TestEncryptString(t *testing.T) {
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	pv, data, err := m.encryptCredentials("secret-token")
	require.NoError(t, err)
	require.Equal(t, uint64(1), pv)
	require.NotEmpty(t, data)
}

func TestEncryptStruct(t *testing.T) {
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	pv, data, err := m.encryptCredentials(struct {
		Token string `json:"token"`
	}{"abc123"})
	require.NoError(t, err)
	require.Equal(t, uint64(1), pv)
	require.NotEmpty(t, data)
}

///////////////////////////////////////////////////////////////////////////////
// TESTS - decryptCredentials

func TestDecryptEmpty(t *testing.T) {
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	var out json.RawMessage
	require.NoError(t, m.decryptCredentials([]byte{}, 1, &out))
	require.Nil(t, out)
}

func TestDecryptNoPassphrase(t *testing.T) {
	// Encrypt with a passphrase, then try to decrypt without one.
	enc := newCryptManager(t, WithPassphrase(1, "passphrase"))
	_, data, err := enc.encryptCredentials("secret")
	require.NoError(t, err)

	dec := newCryptManager(t)
	var out json.RawMessage
	require.ErrorIs(t, dec.decryptCredentials(data, 1, &out), auth.ErrServiceUnavailable)
}

func TestDecryptWrongPassphraseVersion(t *testing.T) {
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	_, data, err := m.encryptCredentials("secret")
	require.NoError(t, err)

	var out json.RawMessage
	require.ErrorIs(t, m.decryptCredentials(data, 99, &out), auth.ErrBadParameter)
}

func TestDecryptWrongType(t *testing.T) {
	// Credentials which don't decode into the value are rejected
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	pv, data, err := m.encryptCredentials("secret")
	require.NoError(t, err)

	var out int
	require.ErrorIs(t, m.decryptCredentials(data, pv, &out), auth.ErrBadParameter)
}

///////////////////////////////////////////////////////////////////////////////
// TESTS - round-trip

func TestRoundTripString(t *testing.T) {
	m := newCryptManager(t, WithPassphrase(1, "passphrase"))

	pv, data, err := m.encryptCredentials("my-token")
	require.NoError(t, err)

	var out string
	require.NoError(t, m.decryptCredentials(data, pv, &out))
	require.Equal(t, "my-token", out)
}

func TestRoundTripStruct(t *testing.T) {
	type creds struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}

	m := newCryptManager(t, WithPassphrase(1, "passphrase"))
	input := creds{User: "admin", Pass: "hunter2"}

	pv, data, err := m.encryptCredentials(input)
	require.NoError(t, err)

	var output creds
	require.NoError(t, m.decryptCredentials(data, pv, &output))
	require.Equal(t, input, output)
}

func TestRoundTripMultiplePassphrases(t *testing.T) {
	// Encrypt with the latest passphrase version, and decrypt with a manager
	// which knows several versions
	m := newCryptManager(t, WithPassphrase(1, "old-pass"), WithPassphrase(2, "new-pass"))

	pv, data, err := m.encryptCredentials("secret")
	require.NoError(t, err)
	require.Equal(t, uint64(2), pv)

	var out string
	require.NoError(t, m.decryptCredentials(data, pv, &out))
	require.Equal(t, "secret", out)
}
