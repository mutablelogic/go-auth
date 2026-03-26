package main

import (
	"fmt"
	"os"

	// Packages
	auth "github.com/djthorpe/go-auth/pkg/cmd/auth"
	manager "github.com/djthorpe/go-auth/pkg/cmd/manager"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	version "github.com/mutablelogic/go-server/pkg/version"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type CLI struct {
	ServerCommands
	auth.AuthCommands
	manager.ManagerCommands
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func main() {
	if err := cmd.Main(CLI{}, "Authentication and Authorization Server", version.Version()); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(-1)
	}
}
