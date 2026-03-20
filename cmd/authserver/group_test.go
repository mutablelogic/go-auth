package main

import (
	"testing"

	// Packages
	kong "github.com/alecthomas/kong"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestGroupCommandParsing(t *testing.T) {
	t.Run("UpdateGroupLeavesEnabledUnsetWhenOmitted", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var cli CLI
		parser, err := kong.New(&cli)
		require.NoError(err)

		_, err = parser.Parse([]string{"update-group", "all", "--description", " "})
		require.NoError(err)
		assert.Equal("all", cli.UpdateGroup.ID)
		if assert.NotNil(cli.UpdateGroup.Description) {
			assert.Equal(" ", *cli.UpdateGroup.Description)
		}
		assert.Nil(cli.UpdateGroup.Enabled)
	})

	t.Run("UpdateGroupParsesEnabledTrue", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var cli CLI
		parser, err := kong.New(&cli)
		require.NoError(err)

		_, err = parser.Parse([]string{"update-group", "all", "--enabled"})
		require.NoError(err)
		if assert.NotNil(cli.UpdateGroup.Enabled) {
			assert.True(*cli.UpdateGroup.Enabled)
		}
	})

	t.Run("UpdateGroupParsesEnabledFalse", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var cli CLI
		parser, err := kong.New(&cli)
		require.NoError(err)

		_, err = parser.Parse([]string{"update-group", "all", "--no-enabled"})
		require.NoError(err)
		if assert.NotNil(cli.UpdateGroup.Enabled) {
			assert.False(*cli.UpdateGroup.Enabled)
		}
	})
}
