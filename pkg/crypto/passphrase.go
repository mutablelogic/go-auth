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

package crypto

import (
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Key is a 256-bit encryption key derived from a passphrase.
type Key []byte

// Passphrases keeps certificate passphrases in memory keyed by passphrase
// version. Version 0 is reserved to mean "latest" when retrieving a
// passphrase, so stored versions must start at 1.
type Passphrases struct {
	mu     sync.RWMutex
	values map[uint64]string
}

///////////////////////////////////////////////////////////////////////////////
// CONSTANTS

const (
	// Argon2id parameters (OWASP recommended minimums).
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32 // 256-bit key

	// SaltSize is the length of a random salt in bytes.
	SaltSize = 16

	// MinPassphraseLen is the minimum acceptable passphrase length.
	MinPassphraseLen = 8
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewPassphrases() *Passphrases {
	return &Passphrases{
		values: make(map[uint64]string),
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Set stores a passphrase for a specific version.
func (s *Passphrases) Set(version uint64, passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if version == 0 {
		return fmt.Errorf("passphrase version must be greater than zero")
	} else if err := validatePassphrase(passphrase); err != nil {
		return err
	} else if s.values == nil {
		s.values = make(map[uint64]string)
	} else if _, exists := s.values[version]; exists {
		return fmt.Errorf("passphrase version already exists")
	}

	s.values[version] = passphrase
	return nil
}

// Get returns the passphrase and resolved version for a specific version, or
// the latest passphrase when version is zero. If no passphrase is found,
// version zero and an empty passphrase are returned.
func (s *Passphrases) Get(version uint64) (string, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if version == 0 {
		keys := slices.Sorted(maps.Keys(s.values))
		if len(keys) == 0 {
			return "", 0
		}
		latest := keys[len(keys)-1]
		return s.values[latest], latest
	}

	value, exists := s.values[version]
	if !exists {
		return "", 0
	}

	return value, version
}

// Encrypt resolves a passphrase by version, encrypts the plaintext, and
// returns the resolved passphrase version with the ciphertext encoded as a
// base64 string.
func (s *Passphrases) Encrypt(version uint64, plaintext []byte) (uint64, string, error) {
	passphrase, resolved := s.Get(version)
	if passphrase == "" || resolved == 0 {
		return 0, "", fmt.Errorf("passphrase version not found")
	}
	blob, err := Encrypt(passphrase, plaintext)
	if err != nil {
		return 0, "", err
	}
	return resolved, base64.StdEncoding.EncodeToString(blob), nil
}

// EncryptString resolves a passphrase by version, encrypts the plaintext
// string, and returns the resolved passphrase version with the ciphertext
// encoded as a base64 string.
func (s *Passphrases) EncryptString(version uint64, plaintext string) (uint64, string, error) {
	return s.Encrypt(version, []byte(plaintext))
}

// Decrypt resolves a passphrase by version and decrypts a base64-encoded
// ciphertext produced by Encrypt.
func (s *Passphrases) Decrypt(version uint64, ciphertext string) ([]byte, error) {
	passphrase, resolved := s.Get(version)
	if passphrase == "" || resolved == 0 {
		return nil, fmt.Errorf("passphrase version not found")
	}
	blob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return Decrypt[[]byte](passphrase, blob)
}

// DecryptString resolves a passphrase by version and decrypts a base64-encoded
// ciphertext to a UTF-8 string.
func (s *Passphrases) DecryptString(version uint64, ciphertext string) (string, error) {
	plaintext, err := s.Decrypt(version, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// Keys returns all stored passphrase versions in sorted order.
func (s *Passphrases) Keys() []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return slices.Sorted(maps.Keys(s.values))
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// validatePassphrase checks that the passphrase meets minimum security
// requirements: non-empty, not whitespace-only, and at least
// MinPassphraseLen characters long.
func validatePassphrase(passphrase string) error {
	trimmed := strings.TrimSpace(passphrase)
	if len(trimmed) == 0 {
		return fmt.Errorf("passphrase must not be empty")
	}
	if len(trimmed) < MinPassphraseLen {
		return fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLen)
	}
	return nil
}
