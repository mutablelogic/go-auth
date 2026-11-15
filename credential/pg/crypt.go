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

	// Packages
	auth "github.com/mutablelogic/go-auth"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// encryptCredentials encodes the credentials as JSON and encrypts them with
// the latest passphrase, returning the passphrase version and the encrypted
// data. Empty credentials are not encrypted, and return version zero and no
// data.
func (self *Manager) encryptCredentials(v any) (uint64, []byte, error) {
	// Preserve the zero-value contract for raw credential payloads.
	switch value := v.(type) {
	case nil:
		return 0, []byte{}, nil
	case []byte:
		if len(value) == 0 {
			return 0, []byte{}, nil
		}
	case string:
		if value == "" {
			return 0, []byte{}, nil
		}
	}

	// Turn the credentials into JSON. If the credentials are empty this will
	// return an empty JSON object, which we can treat as an empty byte array.
	data, err := json.Marshal(v)
	if err != nil {
		return 0, nil, auth.ErrBadParameter.Withf("%w", err)
	} else if string(data) == "{}" {
		return 0, []byte{}, nil
	}

	// Check for at least one passphrase configured
	if len(self.passphrases.Keys()) == 0 {
		return 0, nil, auth.ErrServiceUnavailable.With("no encryption passphrase configured for credentials")
	}

	// Encrypt with the latest passphrase version
	if pv, crypted, err := self.passphrases.Encrypt(0, data); err != nil {
		return 0, nil, auth.ErrBadParameter.Withf("%w", err)
	} else {
		return pv, []byte(crypted), nil
	}
}

// decryptCredentials decrypts the data with the passphrase version, and
// decodes the JSON into decrypted. Empty data is not decrypted, and leaves
// decrypted unchanged.
func (self *Manager) decryptCredentials(encrypted []byte, pv uint64, decrypted any) error {
	if len(encrypted) == 0 {
		return nil
	}

	// Check for at least one passphrase configured
	if len(self.passphrases.Keys()) == 0 {
		return auth.ErrServiceUnavailable.With("no encryption passphrase configured for credentials")
	}

	// Decrypt the credentials using the passphrase version and encrypted data, and
	// then unmarshal the JSON into the provided decrypted structure.
	if data, err := self.passphrases.Decrypt(pv, string(encrypted)); err != nil {
		return auth.ErrBadParameter.Withf("%w", err)
	} else if err := json.Unmarshal([]byte(data), decrypted); err != nil {
		return auth.ErrBadParameter.Withf("%w", err)
	} else {
		return nil
	}
}
