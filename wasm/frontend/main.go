package main

import (
	auth "github.com/djthorpe/go-auth/wasm/frontend/pkg/auth"
	dom "github.com/djthorpe/go-wasmbuild"
	js "github.com/djthorpe/go-wasmbuild/pkg/js"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

var frontendAuth *auth.Auth

func main() {
	mvc.New(newApp()).Run()
}

func newApp() any {
	frontendAuth = auth.New()

	root := mvc.HTML("DIV")
	title := mvc.HTML("H1", "User Information")
	message := mvc.HTML("PRE", "Loading user information...")
	actions := mvc.HTML("DIV")
	refreshButton := mvc.HTML("BUTTON", "Refresh")
	logoutButton := mvc.HTML("BUTTON", "Logout")

	refreshButton.SetAttribute("type", "button")
	logoutButton.SetAttribute("type", "button")
	refreshButton.SetAttribute("style", "margin-right: 0.5rem;")
	actions.AppendChild(refreshButton)
	actions.AppendChild(logoutButton)

	root.AppendChild(title)
	root.AppendChild(message)
	root.AppendChild(actions)

	refreshButton.AddEventListener("click", func(dom.Event) {
		message.SetInnerHTML("Refreshing user information...")
		frontendAuth.Refresh(func(userinfo string) {
			renderUserInfo(message, userinfo)
		}, func(err error) {
			renderError(message, err)
		})
	})

	logoutButton.AddEventListener("click", func(dom.Event) {
		message.SetInnerHTML("Signing out...")
		frontendAuth.Logout(func() {
			js.Global().Get("location").Set("href", "/")
		}, func(err error) {
			renderError(message, err)
		})
	})

	frontendAuth.UserInfo(func(userinfo string) {
		renderUserInfo(message, userinfo)
	}, func(err error) {
		renderError(message, err)
	})

	return root
}

func renderUserInfo(target dom.Element, userinfo string) {
	target.SetInnerHTML(userinfo)
}

func renderError(target dom.Element, err error) {
	target.SetInnerHTML(err.Error())
}
