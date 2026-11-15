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
	"os"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_CheckWritable(t *testing.T) {
	path := t.TempDir()
	mgr := &Manager{path: path}

	// A writable directory, which is left empty
	require.NoError(t, mgr.checkWritable())
	entries, err := os.ReadDir(path)
	require.NoError(t, err)
	assert.Empty(t, entries)

	// A directory which isn't writable, such as on a read-only filesystem,
	// which New would otherwise have made writable
	if os.Geteuid() == 0 {
		t.Skip("root can write to any directory")
	}
	require.NoError(t, os.Chmod(path, 0o500))
	t.Cleanup(func() { os.Chmod(path, 0o700) })
	assert.ErrorIs(t, mgr.checkWritable(), auth.ErrForbidden)
}
