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

package main

import (
	// Packages
	dom "github.com/djthorpe/go-wasmbuild"
	"github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
	"github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func main() {
	mvc.New(App()).Run()
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type app struct {
	mvc.View
}

///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES

const (
	AppView = "app-view"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func init() {
	mvc.RegisterView(AppView, func(element dom.Element) mvc.View {
		return mvc.NewViewWithElement(new(app), element, nil)
	})
}

func App() mvc.View {
	header := carbon.Header(
		carbon.HeaderNavItem("#auth", "Auth"),
		carbon.HeaderNavItem("#ldap", "LDAP"),
		carbon.HeaderNavItem("#cert", "Cert"),
	).SetLabel("/", "Authentication", "Manager")
	sidenav := carbon.SideNav(
		carbon.SideNavGroup("Users",
			carbon.SideNavGroupItem("#active", "Active Users"),
			carbon.SideNavGroupItem("#inactive", "Inactive Users"),
			carbon.SideNavGroupItem("#sessions", "Sessions"),
			carbon.SideNavGroupItem("#keys", "API Keys"),
		),
		carbon.SideNavGroup("Groups",
			carbon.SideNavGroupItem("#groups", "Groups"),
			carbon.SideNavGroupItem("#scopes", "Scopes"),
		),
	)
	content := carbon.Section(
		mvc.WithStyle("min-height:100vh"),
		carbon.With(carbon.ThemeG10),
		carbon.Head(1, "hello, world!"),
	)
	return types.Ptr(app{
		View: carbon.Page(
			carbon.With(carbon.ThemeG90),
			header,
			sidenav,
			content,
		),
	})
}
