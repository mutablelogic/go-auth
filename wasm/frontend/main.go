package main

import (
	auth "github.com/djthorpe/go-auth/wasm/frontend/pkg/auth"
	dom "github.com/djthorpe/go-wasmbuild"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	js "github.com/djthorpe/go-wasmbuild/pkg/js"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

var frontendAuth *auth.Auth

func main() {
	mvc.New(app()...).Run()
}

func app() []any {
	headerNavItem := carbon.HeaderNavItem("#auth", "Auth")
	return []any{
		carbon.Header(
			carbon.With(carbon.ThemeG90),
			headerNavItem,
		).
			SetLabel("/wasm_exec.html", "Go Auth", "Console").
			SetActive(headerNavItem),
	}
}

func newApp() any {
	frontendAuth = auth.New()
	js.Global().Get("document").Get("body").Get("classList").Call("add", "app-page")

	title := carbon.Head(2, "User Information")
	summary := carbon.Lead("Authenticated session details for the current user.")
	message := mvc.HTML("PRE", "Loading user information...")
	message.SetClassName("app-payload")

	refreshButton := carbon.Button(carbon.With(carbon.KindPrimary), "Refresh")
	logoutButton := carbon.Button(carbon.With(carbon.KindSecondary), "Logout")
	actions := mvc.HTML("DIV", mvc.WithClass("app-actions"), refreshButton, logoutButton)

	refreshButton.AddEventListener(carbon.EventClick, func(dom.Event) {
		message.SetInnerHTML("Refreshing user information...")
		frontendAuth.Refresh(func(userinfo string) {
			renderUserInfo(message, userinfo)
		}, func(err error) {
			renderError(message, err)
		})
	})

	logoutButton.AddEventListener(carbon.EventClick, func(dom.Event) {
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

	return carbon.Section(
		mvc.WithStyle("min-height:100vh"),
		carbon.Page(
			mvc.WithClass("app-shell"),
			title,
			summary,
			message,
			actions,
		),
	)
}

func renderUserInfo(target dom.Element, userinfo string) {
	target.SetInnerHTML(userinfo)
}

func renderError(target dom.Element, err error) {
	target.SetInnerHTML(err.Error())
}
