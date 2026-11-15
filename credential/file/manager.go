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

package file

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	crypto "github.com/mutablelogic/go-auth/crypto"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Manager stores credentials in files in a directory, one for each key,
// encrypted with a passphrase. Each file is a record: the passphrase
// version, the credential's description, which isn't encrypted, and the
// encrypted credential.
type Manager struct {
	opt
	sync.Mutex
	path string
}

var _ credential.CredentialProvider = (*Manager)(nil)
var _ credential.CredentialManager = (*Manager)(nil)
var _ credential.CredentialRotator = (*Manager)(nil)
var _ credential.CredentialDecrypter = (*Manager)(nil)

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// dirPerm is the permission of the directory, and filePerm of each
	// credential file, so that only their owner can read them
	dirPerm  = 0o700
	filePerm = 0o600
)

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a manager for credentials in the directory at the path. The
// directory is created when it doesn't exist, its permissions are set so
// that only its owner can access it, and it must be writable.
func New(path string, opts ...Opt) (_ *Manager, err error) {
	self := new(Manager)
	if err := self.opt.apply(opts); err != nil {
		return nil, err
	}
	self.path = path

	// Trace creating the manager, which needs the tracer from the options
	_, endSpan := otel.StartSpan(self.tracer, context.Background(), "credential.file.New",
		attribute.String("path", self.path),
	)
	defer func() { endSpan(err) }()

	// Check the path
	if self.path == "" {
		return nil, auth.ErrBadParameter.With("credential path is required")
	} else if path, err := filepath.Abs(self.path); err != nil {
		return nil, auth.ErrBadParameter.Withf("credential path %q: %w", self.path, err)
	} else {
		self.path = path
	}

	// Create the directory when it doesn't exist, and set its permissions,
	// which MkdirAll doesn't change when it already exists
	info, err := os.Stat(self.path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(self.path, dirPerm); err != nil {
			return nil, pathErr(self.path, err)
		}
		info, err = os.Stat(self.path)
	}
	if err != nil {
		return nil, pathErr(self.path, err)
	} else if !info.IsDir() {
		return nil, auth.ErrBadParameter.Withf("credential path %q is not a directory", self.path)
	} else if info.Mode().Perm() != dirPerm {
		if err := os.Chmod(self.path, dirPerm); err != nil {
			return nil, pathErr(self.path, err)
		}
	}

	// Check the directory is writable, by writing a file, which also finds
	// a read-only filesystem
	if err := self.checkWritable(); err != nil {
		return nil, err
	}

	// Return success
	return self, nil
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Path returns the directory the credentials are stored in
func (self *Manager) Path() string {
	return self.path
}

// Expand replaces each $KEY or ${KEY} placeholder in the value with the
// credential for the key, which must be a string, or with the environment
// variable, with WithEnv, when there is no file for it. Keys containing "-"
// must use the ${KEY} form. Returns an error, rather than a partly expanded
// value, if a placeholder is not a valid key, or its credential does not
// exist or is not a string.
func (self *Manager) Expand(ctx context.Context, value string) (_ string, err error) {
	// The value isn't recorded, as it may contain secrets, only the keys of
	// the credentials used
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.file.Expand")
	defer func() { endSpan(err) }()

	var result error
	cache := make(map[string]string)
	defer func() {
		trace.SpanFromContext(ctx).SetAttributes(attribute.StringSlice("keys", slices.Sorted(maps.Keys(cache))))
	}()
	expanded := os.Expand(value, func(name string) string {
		if result != nil {
			return ""
		} else if value, exists := cache[name]; exists {
			return value
		} else if value, err := self.lookup(ctx, name); err != nil {
			result = err
			return ""
		} else {
			cache[name] = value
			return value
		}
	})
	if result != nil {
		return "", result
	}
	return expanded, nil
}

// Get returns the credential for the key, as JSON, or the environment
// variable's value, with WithEnv, when there is no file for it. Returns an
// error if the key isn't valid, or the credential doesn't exist.
func (self *Manager) Get(ctx context.Context, key string) (_ json.RawMessage, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.file.Get",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return nil, err
	}
	data, err := self.read(key)
	if errors.Is(err, auth.ErrNotFound) && self.env != nil {
		return self.env.Get(ctx, key)
	}
	return data, err
}

// Set encrypts the credential with the latest passphrase, and writes it to
// the key's file, keeping its description, replacing any credential with
// the key. Returns an error if the key isn't valid, the value isn't JSON, or
// there is no passphrase.
func (self *Manager) Set(ctx context.Context, key string, value json.RawMessage) (err error) {
	_, endSpan := otel.StartSpan(self.tracer, ctx, "credential.file.Set",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	} else if !json.Valid(value) {
		return auth.ErrBadParameter.Withf("credential %q is not JSON", key)
	}

	// Encrypt with the latest passphrase
	passphrase, version := self.passphrases.Get(0)
	if version == 0 {
		return errNoPassphrase(key)
	}
	encrypted, err := crypto.Encrypt(passphrase, []byte(value))
	if err != nil {
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	}

	// Keep the description of the credential it replaces, unless its file
	// isn't valid, which is replaced
	self.Lock()
	defer self.Unlock()
	description := ""
	if existing, err := self.readRecord(key); err == nil {
		description = existing.description
	} else if !errors.Is(err, auth.ErrNotFound) && !errors.Is(err, errInvalid) {
		return err
	}
	return self.write(key, record{version: version, description: description, encrypted: encrypted}.encode())
}

// List returns the stored credentials, in key order, with their
// descriptions, without reading or decrypting their values. Files whose names aren't keys, such as temporary files,
// aren't listed.
func (self *Manager) List(ctx context.Context) (_ []credential.Credential, err error) {
	_, endSpan := otel.StartSpan(self.tracer, ctx, "credential.file.List")
	defer func() { endSpan(err) }()

	entries, err := os.ReadDir(self.path)
	if err != nil {
		return nil, auth.ErrInternalServerError.Withf("credential path %q: %w", self.path, err)
	}

	// A credential needs rotating when it's encrypted with an older
	// passphrase than the latest
	_, latest := self.passphrases.Get(0)
	result := make([]credential.Credential, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || validateKey(entry.Name()) != nil {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, auth.ErrInternalServerError.Withf("credential %q: %w", entry.Name(), err)
		}
		// The description is in the file, which is listed without it when
		// it isn't valid
		description, rotate := "", false
		if r, err := self.readRecord(entry.Name()); err == nil {
			description, rotate = r.description, latest != 0 && r.version != latest
		} else if errors.Is(err, auth.ErrNotFound) {
			continue
		} else if !errors.Is(err, errInvalid) {
			return nil, err
		}
		result = append(result, credential.Credential{Key: entry.Name(), Description: description, UpdatedAt: info.ModTime().UTC(), Rotate: rotate})
	}
	return result, nil
}

// Delete removes the file for the key, and returns ErrNotFound when there
// isn't one
func (self *Manager) Delete(ctx context.Context, key string) (err error) {
	_, endSpan := otel.StartSpan(self.tracer, ctx, "credential.file.Delete",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	}
	self.Lock()
	defer self.Unlock()
	if err := os.Remove(filepath.Join(self.path, key)); errors.Is(err, fs.ErrNotExist) {
		return auth.ErrNotFound.Withf("credential %q not found", key)
	} else if err != nil {
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	}
	return nil
}

// Describe sets the description of the key's credential, in its file,
// which isn't encrypted, as a description isn't secret, so it needs no
// passphrase, or removes it, when it's empty, and returns ErrNotFound when
// there's no credential
func (self *Manager) Describe(ctx context.Context, key, description string) (err error) {
	_, endSpan := otel.StartSpan(self.tracer, ctx, "credential.file.Describe",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	}
	description = strings.TrimSpace(description)
	if len(description) > maxDescription {
		return auth.ErrBadParameter.Withf("credential %q: its description is more than %d bytes", key, maxDescription)
	} else if !utf8.ValidString(description) {
		return auth.ErrBadParameter.Withf("credential %q: its description isn't UTF-8", key)
	}

	// The encrypted value is written again, as it is
	self.Lock()
	defer self.Unlock()
	r, err := self.readRecord(key)
	if err != nil {
		return err
	}
	r.description = description
	return self.write(key, r.encode())
}

// Decrypt returns the credential for the key, as JSON, when the passphrase
// is the one it was encrypted with, compared in constant time, or
// ErrForbidden when it isn't
func (self *Manager) Decrypt(ctx context.Context, key, passphrase string) (_ json.RawMessage, err error) {
	_, endSpan := otel.StartSpan(self.tracer, ctx, "credential.file.Decrypt",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return nil, err
	}
	r, err := self.readRecord(key)
	if err != nil {
		return nil, err
	}

	// The passphrase must be the one for the file's version, which must be
	// registered. An empty passphrase never matches.
	stored, resolved := self.passphrases.Get(r.version)
	if r.version == 0 || resolved != r.version || passphrase == "" || subtle.ConstantTimeCompare([]byte(stored), []byte(passphrase)) != 1 {
		return nil, auth.ErrForbidden.With("invalid passphrase")
	}
	return self.decrypt(key, r)
}

// Rotate re-encrypts the file for the key with the latest passphrase,
// keeping its description, and returns ErrNotModified when it already uses
// it, or ErrNotFound when there isn't one
func (self *Manager) Rotate(ctx context.Context, key string) (err error) {
	_, endSpan := otel.StartSpan(self.tracer, ctx, "credential.file.Rotate",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	}
	passphrase, latest := self.passphrases.Get(0)
	if latest == 0 {
		return errNoPassphrase(key)
	}

	// Hold the lock while reading, so a Set in the meantime isn't replaced
	self.Lock()
	defer self.Unlock()
	r, err := self.readRecord(key)
	if err != nil {
		return err
	} else if r.version == latest {
		return auth.ErrNotModified.Withf("credential %q already uses the latest passphrase version", key)
	}
	data, err := self.decrypt(key, r)
	if err != nil {
		return err
	}
	encrypted, err := crypto.Encrypt(passphrase, []byte(data))
	if err != nil {
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	}
	return self.write(key, record{version: latest, description: r.description, encrypted: encrypted}.encode())
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// checkWritable creates and removes a temporary file in the directory, and
// returns ErrForbidden when it can't be created
func (self *Manager) checkWritable() error {
	// The temporary file's name starts with ".", which isn't a valid key
	tmp, err := os.CreateTemp(self.path, ".writable.*")
	if err != nil {
		return auth.ErrForbidden.Withf("credential path %q is not writable: %w", self.path, err)
	}
	name := tmp.Name()
	if err := errors.Join(tmp.Close(), os.Remove(name)); err != nil {
		return auth.ErrInternalServerError.Withf("credential path %q: %w", self.path, err)
	}
	return nil
}

// pathErr returns ErrForbidden for a permission error on the path, or else
// ErrInternalServerError
func pathErr(path string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return auth.ErrForbidden.Withf("credential path %q: %w", path, err)
	}
	return auth.ErrInternalServerError.Withf("credential path %q: %w", path, err)
}

// lookup returns the credential for the placeholder name, which must be a
// string. An environment variable is used as it is, as it's a string even
// when it looks like JSON, such as a number.
func (self *Manager) lookup(ctx context.Context, name string) (string, error) {
	if err := validateKey(name); err != nil {
		return "", auth.ErrBadParameter.Withf("invalid credential placeholder %q", name)
	}
	data, err := self.read(name)
	if errors.Is(err, auth.ErrNotFound) && self.env != nil {
		return self.env.Expand(ctx, "${"+name+"}")
	} else if err != nil {
		return "", err
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return "", auth.ErrBadParameter.Withf("credential %q is not a string", name)
	}
	return value, nil
}

// read returns the decrypted credential for the key, or ErrNotFound when
// there is no file for it
func (self *Manager) read(key string) (json.RawMessage, error) {
	r, err := self.readRecord(key)
	if err != nil {
		return nil, err
	}
	return self.decrypt(key, r)
}

// readRecord returns the record of the key's file, ErrNotFound when there
// isn't one, or an error which is errInvalid, as ErrInternalServerError,
// when it isn't a record
func (self *Manager) readRecord(key string) (*record, error) {
	data, err := os.ReadFile(filepath.Join(self.path, key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, auth.ErrNotFound.Withf("credential %q not found", key)
	} else if err != nil {
		return nil, auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	}
	r, err := decodeRecord(data)
	if err != nil {
		return nil, auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	}
	return r, nil
}

// decrypt returns the record's credential, decrypted with the passphrase
// for its version
func (self *Manager) decrypt(key string, r *record) (json.RawMessage, error) {
	passphrase, resolved := self.passphrases.Get(r.version)
	if len(self.passphrases.Keys()) == 0 {
		return nil, errNoPassphrase(key)
	} else if r.version == 0 || resolved != r.version {
		return nil, auth.ErrServiceUnavailable.Withf("credential %q: no passphrase for version %d", key, r.version)
	}
	decrypted, err := crypto.Decrypt[[]byte](passphrase, r.encrypted)
	if err != nil {
		return nil, auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	} else if !json.Valid(decrypted) {
		return nil, auth.ErrInternalServerError.Withf("credential %q is not JSON", key)
	}
	return json.RawMessage(decrypted), nil
}

// write replaces the key's file with the data, by writing a temporary file
// in the directory and renaming it
func (self *Manager) write(key string, data []byte) (err error) {
	// The temporary file's name starts with ".", which isn't a valid key
	tmp, err := os.CreateTemp(self.path, "."+key+".*")
	if err != nil {
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	}
	defer func() {
		if err != nil {
			os.Remove(tmp.Name())
		}
	}()

	// CreateTemp creates the file with permissions 0600 already, but set
	// them in case that changes
	if err := tmp.Chmod(filePerm); err != nil {
		tmp.Close()
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	} else if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	} else if err := tmp.Sync(); err != nil {
		tmp.Close()
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	} else if err := tmp.Close(); err != nil {
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	} else if err := os.Rename(tmp.Name(), filepath.Join(self.path, key)); err != nil {
		return auth.ErrInternalServerError.Withf("credential %q: %w", key, err)
	}

	// Return success
	return nil
}

// validateKey returns an error if the key, which is also the file's name,
// isn't an identifier, so it can't be a path, or start with "."
func validateKey(key string) error {
	if key != strings.TrimSpace(key) || !types.IsIdentifier(key) {
		return auth.ErrBadParameter.Withf("credential key %q must be an identifier", key)
	}
	return nil
}

// errNoPassphrase is the error when there's no passphrase, so credentials
// can't be read or written
func errNoPassphrase(key string) error {
	return auth.ErrServiceUnavailable.Withf("cannot use credential %q: no encryption passphrase configured for credentials", key)
}
