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

package credential

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Features is what a credential manager can do, beyond storing, listing and
// deleting credentials, which a server says in its configuration, so its
// web UI only offers what the manager can do
type Features struct {
	Backend string `json:"backend" help:"The manager's backend, such as file, pg, aws or bitwarden"`
	Decrypt bool   `json:"decrypt" help:"Whether a credential's value can be read, with the passphrase it was encrypted with"`
	Rotate  bool   `json:"rotate" help:"Whether a credential can be re-encrypted with the latest passphrase"`
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// FeaturesOf returns what the manager of the backend, such as file, can do,
// from the interfaces it implements: CredentialDecrypter, and
// CredentialRotator, which the file and pg managers do, and the others
// don't, as they encrypt with their own keys
func FeaturesOf(backend string, manager CredentialManager) Features {
	_, decrypt := manager.(CredentialDecrypter)
	_, rotate := manager.(CredentialRotator)
	return Features{Backend: backend, Decrypt: decrypt, Rotate: rotate}
}
