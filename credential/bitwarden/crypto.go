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

package bitwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// key is a Bitwarden AES-256-CBC key with an HMAC-SHA256 key, which is 64
// bytes: the encryption key, then the MAC key
type key struct {
	enc [32]byte
	mac [32]byte
}

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// encTypeAesCbcHmac is the type of an encrypted string which is
	// AES-256-CBC with an HMAC-SHA256, written "2.iv|data|mac"
	encTypeAesCbcHmac = "2"
)

var (
	errDecrypt = errors.New("decryption failed")
)

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// newKey returns the key from its 64 bytes
func newKey(data []byte) (*key, error) {
	if len(data) != 64 {
		return nil, errors.New("unsupported key: only 64-byte AES-256-CBC-HMAC keys are supported")
	}
	k := new(key)
	copy(k.enc[:], data[:32])
	copy(k.mac[:], data[32:])
	return k, nil
}

// deriveShareableKey derives a key from a 16-byte secret, as Bitwarden does:
// HMAC-SHA256 of the secret, keyed with "bitwarden-" and the name, expanded
// to 64 bytes with HKDF-SHA256 and the info
func deriveShareableKey(secret []byte, name, info string) (*key, error) {
	mac := hmac.New(sha256.New, []byte("bitwarden-"+name))
	mac.Write(secret)
	data, err := hkdf.Expand(sha256.New, mac.Sum(nil), info, 64)
	if err != nil {
		return nil, err
	}
	return newKey(data)
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// encrypt encrypts the data with a random IV, and returns it as an encrypted
// string, "2.iv|data|mac", with each part in base64
func (k *key) encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(k.enc[:])
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	// Pad with PKCS#7, and encrypt
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	data := append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(padding)}, padding)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)

	return encTypeAesCbcHmac + "." + strings.Join([]string{
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(data),
		base64.StdEncoding.EncodeToString(k.sum(iv, data)),
	}, "|"), nil
}

// decrypt decrypts an encrypted string, "2.iv|data|mac", after checking its
// MAC. Other types of encrypted string aren't supported.
func (k *key) decrypt(value string) ([]byte, error) {
	encType, rest, ok := strings.Cut(value, ".")
	if !ok || encType != encTypeAesCbcHmac {
		return nil, errors.New("unsupported encrypted string: only type 2 (AES-256-CBC-HMAC) is supported")
	}
	parts := strings.Split(rest, "|")
	if len(parts) != 3 {
		return nil, errDecrypt
	}
	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(iv) != aes.BlockSize {
		return nil, errDecrypt
	}
	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errDecrypt
	}
	mac, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(mac, k.sum(iv, data)) {
		return nil, errDecrypt
	}

	// Decrypt, and remove the PKCS#7 padding
	block, err := aes.NewCipher(k.enc[:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, data)
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize || !bytes.Equal(plaintext[len(plaintext)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		return nil, errDecrypt
	}
	return plaintext[:len(plaintext)-padding], nil
}

// sum returns the HMAC-SHA256 of the IV and the encrypted data
func (k *key) sum(iv, data []byte) []byte {
	mac := hmac.New(sha256.New, k.mac[:])
	mac.Write(iv)
	mac.Write(data)
	return mac.Sum(nil)
}

// bytes returns the key's 64 bytes
func (k *key) bytes() []byte {
	return append(bytes.Clone(k.enc[:]), k.mac[:]...)
}
