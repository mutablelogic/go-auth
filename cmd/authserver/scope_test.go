package main

import (
	"testing"

	// Packages
	kong "github.com/alecthomas/kong"
	require "github.com/stretchr/testify/require"
)

func TestListScopesCommandParse(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"scopes", "--q", "user.read", "--offset", "2", "--limit", "5"})
	require.NoError(t, err)

	require.Equal(t, "user.read", cli.ScopeCommands.Scopes.Q)
	require.Equal(t, uint64(2), cli.ScopeCommands.Scopes.Offset)
	require.NotNil(t, cli.ScopeCommands.Scopes.Limit)
	require.Equal(t, uint64(5), *cli.ScopeCommands.Scopes.Limit)
}
