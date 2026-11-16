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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// signin is the state of a sign-in with a redirect provider, which is in a
// cookie, sealed, while the person is at the provider
type signin struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
	Return   string `json:"r,omitempty"`
}

// sealer seals a sign-in, with AES-GCM, so it can't be read, or changed,
// and opens it
type sealer struct {
	aead cipher.AEAD
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var errCookie = errors.New("the sign-in's cookie isn't valid, or has expired")

// What a value is sealed for
const (
	purposeSignIn = "signin"
	purposeClient = "client"
	purposeCode   = "code"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// newSealer returns a sealer with the key, of 32 bytes
func newSealer(key []byte) (*sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// seal returns the sign-in, sealed, as a cookie's value
func (s *sealer) seal(in signin) (string, error) {
	return s.sealValue(purposeSignIn, in)
}

// open returns the sign-in a cookie's value is, when it's for the
// provider, and hasn't expired
func (s *sealer) open(value, provider string, now time.Time) (*signin, error) {
	var out signin
	if err := s.openValue(purposeSignIn, value, &out); err != nil || out.Provider != provider || now.Unix() > out.Expires {
		return nil, errCookie
	}
	return &out, nil
}

// sealValue returns the value, as JSON, sealed for the purpose, which it
// can only be opened for, so one of another purpose, such as a client's
// ID, isn't taken for a code
func (s *sealer) sealValue(purpose string, v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, data, []byte(purpose))), nil
}

// openValue opens a value sealed for the purpose into v
func (s *sealer) openValue(purpose, value string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(data) < s.aead.NonceSize() {
		return errCookie
	}
	plain, err := s.aead.Open(nil, data[:s.aead.NonceSize()], data[s.aead.NonceSize():], []byte(purpose))
	if err != nil {
		return errCookie
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return errCookie
	}
	return nil
}
