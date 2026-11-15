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

package file_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	file "github.com/mutablelogic/go-auth/credential/file"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

const (
	passphrase = "test passphrase"
)

func Test_New(t *testing.T) {
	t.Run("NoPath", func(t *testing.T) {
		_, err := file.New("", file.WithPassphrase(1, passphrase))
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("Create", func(t *testing.T) {
		// A directory which doesn't exist is created, with permissions 0700
		path := filepath.Join(t.TempDir(), "a", "credentials")
		mgr, err := file.New(path)
		require.NoError(t, err)
		assert.Equal(t, path, mgr.Path())
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	})

	t.Run("Chmod", func(t *testing.T) {
		// A directory which exists has its permissions set to 0700
		path := t.TempDir()
		require.NoError(t, os.Chmod(path, 0o755))
		_, err := file.New(path)
		require.NoError(t, err)
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	})

	t.Run("NotDirectory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		_, err := file.New(path)
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("NotCreatable", func(t *testing.T) {
		// A directory which can't be created, in a read-only parent
		if os.Geteuid() == 0 {
			t.Skip("root can write to any directory")
		}
		parent := t.TempDir()
		require.NoError(t, os.Chmod(parent, 0o500))
		t.Cleanup(func() { os.Chmod(parent, 0o700) })
		_, err := file.New(filepath.Join(parent, "credentials"))
		assert.ErrorIs(t, err, auth.ErrForbidden)
	})

	t.Run("EmptyPassphrase", func(t *testing.T) {
		_, err := file.New(t.TempDir(), file.WithPassphrase(1, ""))
		assert.Error(t, err)
	})
}

func Test_SetGet(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	mgr, err := file.New(path, file.WithPassphrase(1, passphrase))
	require.NoError(t, err)

	t.Run("RoundTrip", func(t *testing.T) {
		for key, value := range map[string]string{
			"string": `"secret"`,
			"object": `{"user":"admin","password":"secret"}`,
			"number": `123`,
		} {
			require.NoError(t, mgr.Set(ctx, key, json.RawMessage(value)))
			got, err := mgr.Get(ctx, key)
			require.NoError(t, err)
			assert.JSONEq(t, value, string(got))
		}
	})

	t.Run("File", func(t *testing.T) {
		// The file is only readable by its owner, starts with the passphrase
		// version, and doesn't contain the credential in plain text
		require.NoError(t, mgr.Set(ctx, "plain", json.RawMessage(`"plaintext-secret"`)))
		info, err := os.Stat(filepath.Join(path, "plain"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		data, err := os.ReadFile(filepath.Join(path, "plain"))
		require.NoError(t, err)
		assert.Equal(t, uint64(1), binary.BigEndian.Uint64(data[:8]))
		assert.NotContains(t, string(data), "plaintext-secret")

		// No temporary files are left behind
		entries, err := os.ReadDir(path)
		require.NoError(t, err)
		for _, entry := range entries {
			assert.False(t, strings.HasPrefix(entry.Name(), "."), entry.Name())
		}
	})

	t.Run("Replace", func(t *testing.T) {
		require.NoError(t, mgr.Set(ctx, "replace", json.RawMessage(`"one"`)))
		require.NoError(t, mgr.Set(ctx, "replace", json.RawMessage(`"two"`)))
		got, err := mgr.Get(ctx, "replace")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"two"`), got)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := mgr.Get(ctx, "missing")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})

	t.Run("InvalidKey", func(t *testing.T) {
		for _, key := range []string{"", "../escape", ".hidden", "a/b", " spaced", "1abc"} {
			_, err := mgr.Get(ctx, key)
			assert.ErrorIs(t, err, auth.ErrBadParameter, "key %q", key)
			assert.ErrorIs(t, mgr.Set(ctx, key, json.RawMessage(`"x"`)), auth.ErrBadParameter, "key %q", key)
		}
	})

	t.Run("NotJSON", func(t *testing.T) {
		assert.ErrorIs(t, mgr.Set(ctx, "notjson", json.RawMessage(`not json`)), auth.ErrBadParameter)
	})

	t.Run("Corrupt", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(path, "corrupt"), []byte{0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3}, 0o600))
		_, err := mgr.Get(ctx, "corrupt")
		assert.ErrorIs(t, err, auth.ErrInternalServerError)
		require.NoError(t, os.WriteFile(filepath.Join(path, "short"), []byte{0, 1}, 0o600))
		_, err = mgr.Get(ctx, "short")
		assert.ErrorIs(t, err, auth.ErrInternalServerError)
	})
}

func Test_List(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	mgr, err := file.New(path, file.WithPassphrase(1, passphrase), file.WithEnv())
	require.NoError(t, err)
	t.Setenv("GOAUTH_TEST_LIST_ENV", "from-env")

	// Empty, and the environment isn't listed
	list, err := mgr.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)

	// Credentials, in key order, but not other files or directories
	require.NoError(t, mgr.Set(ctx, "zeta", json.RawMessage(`"z"`)))
	require.NoError(t, mgr.Set(ctx, "alpha", json.RawMessage(`"a"`)))
	require.NoError(t, os.WriteFile(filepath.Join(path, ".alpha.123"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(path, "not a key"), nil, 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(path, "dir"), 0o700))
	list, err = mgr.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "alpha", list[0].Key)
	assert.Equal(t, "zeta", list[1].Key)
	assert.False(t, list[0].UpdatedAt.IsZero())
}

func Test_DeleteRotate(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	v1, err := file.New(path, file.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	require.NoError(t, v1.Set(ctx, "key", json.RawMessage(`"value"`)))

	t.Run("RotateLatest", func(t *testing.T) {
		assert.ErrorIs(t, v1.Rotate(ctx, "key"), auth.ErrNotModified)
	})

	t.Run("Rotate", func(t *testing.T) {
		// With a new passphrase, the file is re-encrypted with it, and can
		// be read with only the new passphrase
		v2, err := file.New(path, file.WithPassphrase(1, passphrase), file.WithPassphrase(2, "second passphrase"))
		require.NoError(t, err)
		require.NoError(t, v2.Rotate(ctx, "key"))
		data, err := os.ReadFile(filepath.Join(path, "key"))
		require.NoError(t, err)
		assert.Equal(t, uint64(2), binary.BigEndian.Uint64(data[:8]))
		assert.ErrorIs(t, v2.Rotate(ctx, "key"), auth.ErrNotModified)

		only2, err := file.New(path, file.WithPassphrase(2, "second passphrase"))
		require.NoError(t, err)
		got, err := only2.Get(ctx, "key")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"value"`), got)
	})

	t.Run("RotateMissing", func(t *testing.T) {
		assert.ErrorIs(t, v1.Rotate(ctx, "missing"), auth.ErrNotFound)
		assert.ErrorIs(t, v1.Rotate(ctx, "a/b"), auth.ErrBadParameter)
		none, err := file.New(path)
		require.NoError(t, err)
		assert.ErrorIs(t, none.Rotate(ctx, "key"), auth.ErrServiceUnavailable)
	})

	t.Run("Delete", func(t *testing.T) {
		require.NoError(t, v1.Delete(ctx, "key"))
		_, err := os.Stat(filepath.Join(path, "key"))
		assert.ErrorIs(t, err, os.ErrNotExist)
		assert.ErrorIs(t, v1.Delete(ctx, "key"), auth.ErrNotFound)
		assert.ErrorIs(t, v1.Delete(ctx, "../escape"), auth.ErrBadParameter)
	})
}

func Test_Describe(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	mgr, err := file.New(path, file.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	require.NoError(t, mgr.Set(ctx, "token", json.RawMessage(`"secret"`)))

	// The description is in the credential's own file, not encrypted, and
	// there's no other file
	require.NoError(t, mgr.Describe(ctx, "token", "  The API token  "))
	data, err := os.ReadFile(filepath.Join(path, "token"))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), binary.BigEndian.Uint64(data[:8]))
	assert.Contains(t, string(data), "The API token")
	assert.NotContains(t, string(data), "secret")
	entries, err := os.ReadDir(path)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	list, err := mgr.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "The API token", list[0].Description)

	// The value is the same, and it's kept when the value is replaced
	got, err := mgr.Get(ctx, "token")
	require.NoError(t, err)
	assert.Equal(t, json.RawMessage(`"secret"`), got)
	require.NoError(t, mgr.Set(ctx, "token", json.RawMessage(`"new"`)))
	list, err = mgr.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, "The API token", list[0].Description)

	// A description needs no passphrase, as the value isn't decrypted
	none, err := file.New(path)
	require.NoError(t, err)
	require.NoError(t, none.Describe(ctx, "token", "Without a passphrase"))
	got, err = mgr.Get(ctx, "token")
	require.NoError(t, err)
	assert.Equal(t, json.RawMessage(`"new"`), got)

	// Rotating keeps it
	v2, err := file.New(path, file.WithPassphrase(1, passphrase), file.WithPassphrase(2, "second passphrase"))
	require.NoError(t, err)
	require.NoError(t, v2.Rotate(ctx, "token"))
	list, err = v2.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, "Without a passphrase", list[0].Description)

	// An empty description removes it
	require.NoError(t, v2.Describe(ctx, "token", ""))
	list, err = v2.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list[0].Description)

	assert.ErrorIs(t, mgr.Describe(ctx, "missing", "x"), auth.ErrNotFound)
	assert.ErrorIs(t, mgr.Describe(ctx, "../x", "x"), auth.ErrBadParameter)
	assert.ErrorIs(t, mgr.Describe(ctx, "token", strings.Repeat("x", 4097)), auth.ErrBadParameter)
}

func Test_ListRotate(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	v1, err := file.New(path, file.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	require.NoError(t, v1.Set(ctx, "old", json.RawMessage(`"x"`)))

	// With the latest passphrase, it doesn't need rotating
	list, err := v1.List(ctx)
	require.NoError(t, err)
	assert.False(t, list[0].Rotate)

	// With a newer passphrase, it does, until it's rotated
	v2, err := file.New(path, file.WithPassphrase(1, passphrase), file.WithPassphrase(2, "second passphrase"))
	require.NoError(t, err)
	require.NoError(t, v2.Set(ctx, "new", json.RawMessage(`"y"`)))
	list, err = v2.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "new", list[0].Key)
	assert.False(t, list[0].Rotate)
	assert.Equal(t, "old", list[1].Key)
	assert.True(t, list[1].Rotate)
	require.NoError(t, v2.Rotate(ctx, "old"))
	list, err = v2.List(ctx)
	require.NoError(t, err)
	assert.False(t, list[1].Rotate)

	// Without a passphrase, it isn't known
	none, err := file.New(path)
	require.NoError(t, err)
	list, err = none.List(ctx)
	require.NoError(t, err)
	assert.False(t, list[0].Rotate || list[1].Rotate)
}

func Test_Passphrases(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()

	// Written with version 1
	v1, err := file.New(path, file.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	require.NoError(t, v1.Set(ctx, "old", json.RawMessage(`"old"`)))

	t.Run("OlderVersion", func(t *testing.T) {
		// Read with versions 1 and 2, and new credentials use version 2
		v2, err := file.New(path, file.WithPassphrase(1, passphrase), file.WithPassphrase(2, "second passphrase"))
		require.NoError(t, err)
		got, err := v2.Get(ctx, "old")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"old"`), got)

		require.NoError(t, v2.Set(ctx, "new", json.RawMessage(`"new"`)))
		data, err := os.ReadFile(filepath.Join(path, "new"))
		require.NoError(t, err)
		assert.Equal(t, uint64(2), binary.BigEndian.Uint64(data[:8]))
	})

	t.Run("MissingVersion", func(t *testing.T) {
		v2only, err := file.New(path, file.WithPassphrase(2, "second passphrase"))
		require.NoError(t, err)
		_, err = v2only.Get(ctx, "old")
		assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
	})

	t.Run("WrongPassphrase", func(t *testing.T) {
		wrong, err := file.New(path, file.WithPassphrase(1, "wrong passphrase"))
		require.NoError(t, err)
		_, err = wrong.Get(ctx, "old")
		assert.ErrorIs(t, err, auth.ErrInternalServerError)
	})

	t.Run("NoPassphrase", func(t *testing.T) {
		none, err := file.New(path)
		require.NoError(t, err)
		_, err = none.Get(ctx, "old")
		assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
		assert.ErrorIs(t, none.Set(ctx, "old", json.RawMessage(`"x"`)), auth.ErrServiceUnavailable)
	})
}

func Test_Expand(t *testing.T) {
	ctx := context.Background()
	mgr, err := file.New(t.TempDir(), file.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	require.NoError(t, mgr.Set(ctx, "user", json.RawMessage(`"admin"`)))
	require.NoError(t, mgr.Set(ctx, "pass-word", json.RawMessage(`"secret"`)))
	require.NoError(t, mgr.Set(ctx, "object", json.RawMessage(`{"a":1}`)))

	got, err := mgr.Expand(ctx, "postgres://$user:${pass-word}@host/$user")
	require.NoError(t, err)
	assert.Equal(t, "postgres://admin:secret@host/admin", got)

	_, err = mgr.Expand(ctx, "$missing")
	assert.ErrorIs(t, err, auth.ErrNotFound)
	_, err = mgr.Expand(ctx, "$object")
	assert.ErrorIs(t, err, auth.ErrBadParameter)
	_, err = mgr.Expand(ctx, "${1abc}")
	assert.ErrorIs(t, err, auth.ErrBadParameter)
}

func Test_WithEnv(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	t.Setenv("GOAUTH_TEST_ENV_ONLY", "from-env")
	t.Setenv("GOAUTH_TEST_ENV_NUMBER", "123")
	t.Setenv("GOAUTH_TEST_STORED", "from-env")

	mgr, err := file.New(path, file.WithPassphrase(1, passphrase), file.WithEnv())
	require.NoError(t, err)
	require.NoError(t, mgr.Set(ctx, "GOAUTH_TEST_STORED", json.RawMessage(`"from-file"`)))

	t.Run("Get", func(t *testing.T) {
		// A file is used before the environment
		got, err := mgr.Get(ctx, "GOAUTH_TEST_STORED")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"from-file"`), got)
		got, err = mgr.Get(ctx, "GOAUTH_TEST_ENV_ONLY")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"from-env"`), got)
		_, err = mgr.Get(ctx, "GOAUTH_TEST_MISSING")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})

	t.Run("Expand", func(t *testing.T) {
		// An environment variable is expanded as it is, even when it's JSON
		got, err := mgr.Expand(ctx, "$GOAUTH_TEST_STORED ${GOAUTH_TEST_ENV_ONLY} $GOAUTH_TEST_ENV_NUMBER")
		require.NoError(t, err)
		assert.Equal(t, "from-file from-env 123", got)
	})

	t.Run("NoPassphrase", func(t *testing.T) {
		// Without a passphrase, a credential with no file is still read from
		// the environment, but one with a file can't be read
		none, err := file.New(path, file.WithEnv())
		require.NoError(t, err)
		got, err := none.Expand(ctx, "$GOAUTH_TEST_ENV_ONLY")
		require.NoError(t, err)
		assert.Equal(t, "from-env", got)
		_, err = none.Get(ctx, "GOAUTH_TEST_STORED")
		assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
	})

	t.Run("WithoutEnv", func(t *testing.T) {
		without, err := file.New(path, file.WithPassphrase(1, passphrase))
		require.NoError(t, err)
		_, err = without.Get(ctx, "GOAUTH_TEST_ENV_ONLY")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})
}
