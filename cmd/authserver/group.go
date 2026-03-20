package main

import (
	"fmt"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

type GroupCommands struct {
	Groups      ListGroupsCommand  `cmd:"" name:"groups" help:"Get Groups." group:"USERS & GROUPS"`
	CreateGroup CreateGroupCommand `cmd:"" name:"create-group" help:"Create Group." group:"USERS & GROUPS"`
}

type ListGroupsCommand struct {
	schema.GroupListRequest
}

type CreateGroupCommand struct {
	ID string `arg:"" name:"group" help:"Group identifier"`
	schema.GroupMeta
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListGroupsCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	groups, err := client.ListGroups(ctx.Context(), cmd.GroupListRequest)
	if err != nil {
		return err
	}
	fmt.Println(groups)
	return nil
}

func (cmd *CreateGroupCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	group, err := client.CreateGroup(ctx.Context(), schema.GroupInsert{ID: cmd.ID, GroupMeta: cmd.GroupMeta})
	if err != nil {
		return err
	}
	fmt.Println(group)
	return nil
}
