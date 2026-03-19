package main

import (
	"testing"

	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_parseLoginAddress_001(t *testing.T) {
	t.Run("MailboxAddress", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		name, email, err := parseLoginAddress("David Thorpe <a@d>")
		require.NoError(err)
		assert.Equal("David Thorpe", name)
		assert.Equal("a@d", email)
	})

	t.Run("PlainAddress", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		name, email, err := parseLoginAddress("a@d")
		require.NoError(err)
		assert.Empty(name)
		assert.Equal("a@d", email)
	})

	t.Run("InvalidAddress", func(t *testing.T) {
		assert := assert.New(t)

		_, _, err := parseLoginAddress("not an address")
		assert.Error(err)
	})
}
