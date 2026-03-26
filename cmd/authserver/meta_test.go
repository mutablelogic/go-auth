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

func TestAuthorizeCommandParseEndpoint(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"authorize", "https://api.example.test"})
	require.NoError(t, err)
	require.Equal(t, "https://api.example.test", cli.AuthCommands.Authorize.Endpoint)
}

func TestAuthorizeCommandParseRedirect(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"authorize", "--redirect-url", "http://127.0.0.1:9999/callback"})
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:9999/callback", cli.AuthCommands.Authorize.Redirect)
}

func TestRefreshCommandParseEndpoint(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"refresh", "https://api.example.test"})
	require.NoError(t, err)
	require.Equal(t, "https://api.example.test", cli.AuthCommands.Refresh.Endpoint)
}

func TestUserInfoCommandParseEndpoint(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"userinfo", "https://api.example.test"})
	require.NoError(t, err)
	require.Equal(t, "https://api.example.test", cli.AuthCommands.UserInfo.Endpoint)
}

func TestChangesCommandParse(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"changes"})
	require.NoError(t, err)
}

func TestRunCommandParseDefaultNotifyChannel(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"run", "--url", "postgres://example.test/db"})
	require.NoError(t, err)
	require.Equal(t, "backend.table_change", cli.ServerCommands.RunServer.NotifyChannel)
}

func TestRunCommandParseEmptyNotifyChannel(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"run", "--url", "postgres://example.test/db", "--notify-channel", ""})
	require.NoError(t, err)
	require.Equal(t, "", cli.ServerCommands.RunServer.NotifyChannel)
}

func TestRevokeCommandParseEndpoint(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"revoke", "https://api.example.test"})
	require.NoError(t, err)
	require.Equal(t, "https://api.example.test", cli.AuthCommands.Revoke.Endpoint)
}
