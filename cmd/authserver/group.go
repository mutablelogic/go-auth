package main

import (
	"fmt"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

type GroupCommands struct {
	Groups      ListGroupsCommand  `cmd:"" name:"groups" help:"Get Groups." group:"USERS & GROUPS"`
	Group       GetGroupCommand    `cmd:"" name:"group" help:"Get Group." group:"USERS & GROUPS"`
	CreateGroup CreateGroupCommand `cmd:"" name:"group-create" help:"Create Group." group:"USERS & GROUPS"`
	UpdateGroup UpdateGroupCommand `cmd:"" name:"group-update" help:"Update Group." group:"USERS & GROUPS"`
	DeleteGroup DeleteGroupCommand `cmd:"" name:"group-delete" help:"Delete Group." group:"USERS & GROUPS"`
}

type ListGroupsCommand struct {
	schema.GroupListRequest
}

type CreateGroupCommand struct {
	ID string `arg:"" name:"group" help:"Group identifier"`
	schema.GroupMeta
}

type GetGroupCommand struct {
	ID string `arg:"" name:"group" help:"Group identifier"`
}

type UpdateGroupCommand struct {
	GetGroupCommand
	schema.GroupMeta
}

type DeleteGroupCommand struct {
	GetGroupCommand
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListGroupsCommand) Run(ctx server.Cmd) error {
	clients, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	groups, err := clients.manager.ListGroups(ctx.Context(), cmd.GroupListRequest)
	if err != nil {
		return err
	}
	fmt.Println(groups)
	return nil
}

func (cmd *CreateGroupCommand) Run(ctx server.Cmd) error {
	clients, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	group, err := clients.manager.CreateGroup(ctx.Context(), schema.GroupInsert{ID: cmd.ID, GroupMeta: cmd.GroupMeta})
	if err != nil {
		return err
	}
	fmt.Println(group)
	return nil
}

func (cmd *GetGroupCommand) Run(ctx server.Cmd) error {
	clients, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	group, err := clients.manager.GetGroup(ctx.Context(), cmd.ID)
	if err != nil {
		return err
	}
	fmt.Println(group)
	return nil
}

func (cmd *UpdateGroupCommand) Run(ctx server.Cmd) error {
	clients, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	group, err := clients.manager.UpdateGroup(ctx.Context(), cmd.ID, cmd.GroupMeta)
	if err != nil {
		return err
	}
	fmt.Println(group)
	return nil
}

func (cmd *DeleteGroupCommand) Run(ctx server.Cmd) error {
	clients, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	if err := clients.manager.DeleteGroup(ctx.Context(), cmd.ID); err != nil {
		return err
	}
	fmt.Println(cmd.ID)
	return nil
}
