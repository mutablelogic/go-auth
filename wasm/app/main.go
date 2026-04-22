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
	"fmt"
	syscalljs "syscall/js"
	"time"

	// Packages
	dom "github.com/djthorpe/go-wasmbuild"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	js "github.com/djthorpe/go-wasmbuild/pkg/js"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
	auth "github.com/mutablelogic/go-auth/wasm/app/auth"
	mvc2 "github.com/mutablelogic/go-auth/wasm/app/mvc"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES

const (
	BaseURL           = "/api"
	LoginRedirectPath = "/index.html"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func main() {
	// Create an authorization instance and validate the token, if invalid redirect to login page
	auth, err := auth.New(BaseURL, "auth:token")
	if err != nil || !auth.Valid() {
		js.Global().Set("location", LoginRedirectPath)
	}
	mvc.New(App(auth)).Run()
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type app struct {
	mvc.View
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func App(a *auth.Auth) mvc.View {
	a.AddListener(func(evt *mvc2.Event) {
		switch evt.Name {
		case auth.EventRevoke:
			js.Global().Set("location", LoginRedirectPath)
		case auth.EventError:
			showToast("error", "Authentication error", eventMessage(evt.Data), 8*time.Second)
		}
	})

	userMenu := carbon.OverflowMenu(
		mvc.WithID("user-info"),
		carbon.Icon(carbon.IconUserAvatar, carbon.With(carbon.IconSize24)),
	).SetLabel("User account")
	userMenu.Content(
		carbon.OverflowMenuItem("Logout").AddEventListener("click", func(_ dom.Event) {
			a.Revoke()
		}),
	)

	globalnav := carbon.HeaderNavGlobal(
		userMenu,
	)

	header := carbon.Header(
		carbon.HeaderNavItem("#", "Auth"),
		carbon.HeaderNavItem("#ldap", "LDAP"),
		carbon.HeaderNavItem("#cert", "Cert"),
		globalnav,
	).SetLabel("#", "Authentication", "Manager")

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
		carbon.With(carbon.ThemeG10),
		carbon.Page(
			mvc.WithStyle("display:grid;gap:1.5rem;padding:1.5rem 2rem;min-height:100vh"),
			carbon.Head(1, "hello, world!"),
		),
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

func showToast(kind, title, message string, timeout time.Duration) {
	document := js.Global().Get("document")
	if document.IsUndefined() || document.IsNull() {
		return
	}
	container := document.Call("querySelector", "[data-toast-container]")
	if container.IsUndefined() || container.IsNull() {
		container = document.Call("createElement", "div")
		container.Call("setAttribute", "data-toast-container", "")
		container.Call("setAttribute", "style", "position:fixed;top:1rem;right:1rem;display:grid;gap:0.75rem;z-index:10000;max-width:min(28rem,calc(100vw - 2rem));")
		document.Get("body").Call("appendChild", container)
	}

	toast := document.Call("createElement", "cds-toast-notification")
	toast.Call("setAttribute", "kind", kind)
	toast.Call("setAttribute", "low-contrast", "")
	toast.Call("setAttribute", "open", "")

	titleNode := document.Call("createElement", "div")
	titleNode.Call("setAttribute", "slot", "title")
	titleNode.Set("textContent", title)

	subtitleNode := document.Call("createElement", "div")
	subtitleNode.Call("setAttribute", "slot", "subtitle")
	subtitleNode.Set("textContent", message)

	toast.Call("append", titleNode, subtitleNode)
	container.Call("appendChild", toast)

	if timeout <= 0 {
		return
	}

	var removeFn syscalljs.Func
	removeFn = syscalljs.FuncOf(func(this syscalljs.Value, args []syscalljs.Value) any {
		defer removeFn.Release()
		toast.Call("removeAttribute", "open")
		var cleanupFn syscalljs.Func
		cleanupFn = syscalljs.FuncOf(func(this syscalljs.Value, args []syscalljs.Value) any {
			defer cleanupFn.Release()
			toast.Call("remove")
			return nil
		})
		js.Global().Call("setTimeout", cleanupFn, 220)
		return nil
	})
	js.Global().Call("setTimeout", removeFn, timeout.Milliseconds())
}

func eventMessage(value any) string {
	switch value := value.(type) {
	case nil:
		return ""
	case error:
		return value.Error()
	case fmt.Stringer:
		return value.String()
	case string:
		return value
	default:
		return fmt.Sprint(value)
	}
}
