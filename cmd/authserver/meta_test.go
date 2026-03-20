package main

import (
	"testing"

	// Packages
	kong "github.com/alecthomas/kong"
	require "github.com/stretchr/testify/require"
)

func TestUserUpdateMetaParse(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"user-update", "11111111-1111-1111-1111-111111111111", "--meta", "a=b;c=d"})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"a": "b", "c": "d"}, cli.UserCommands.UpdateUser.Meta.Map())
}

func TestUserUpdateMetaParseJSONValues(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"user-update", "11111111-1111-1111-1111-111111111111", "--meta", `a=true;b=false;c=null;d=2`})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"a": true, "b": false, "c": nil, "d": float64(2)}, cli.UserCommands.UpdateUser.Meta.Map())
}

func TestGroupUpdateMetaParse(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"group-update", "admins", "--meta", `{"team":"platform","priority":1}`})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"team": "platform", "priority": float64(1)}, cli.GroupCommands.UpdateGroup.Meta.Map())
}
