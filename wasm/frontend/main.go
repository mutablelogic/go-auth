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
	frontendAuth = auth.New()

	headerNavItem := carbon.HeaderNavItem("#auth", "Auth")
	users := carbon.SideNavLink("#users", "Users")
	groups := carbon.SideNavLink("#groups", "Groups")
	scopes := carbon.SideNavLink("#scopes", "Scopes")
	sideNav := carbon.SideNav(
		users,
		groups,
		scopes,
	)

	router := mvc.Router().
		Active(sideNav).
		Page("#users", newUsersPage(), users).
		Page("#groups", newPlaceholderPage("Groups", "Manage membership and policy assignments for your tenants."), groups).
		Page("#scopes", newPlaceholderPage("Scopes", "Review and curate OAuth scopes available to client applications."), scopes)

	return []any{
		carbon.With(carbon.ThemeG90),
		carbon.Section(
			carbon.Header(
				headerNavItem,
			).SetLabel("/wasm_exec.html", "Go Auth", "Console").SetActive(headerNavItem),
			sideNav,
			carbon.Section(
				router,
			),
		),
	}
}

func newUsersPage() mvc.View {
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

	return carbon.Page(
		mvc.HTML("DIV",
			mvc.WithClass("app-main"),
			title,
			summary,
			message,
			actions,
		),
	)
}

func newPlaceholderPage(titleText, summaryText string) mvc.View {
	return carbon.Page(
		mvc.HTML("DIV",
			mvc.WithClass("app-main"),
			carbon.Head(2, titleText),
			carbon.Lead(summaryText),
			carbon.Para("This section is ready for the next Carbon-backed view."),
		),
	)
}

func renderUserInfo(target dom.Element, userinfo string) {
	target.SetInnerHTML(userinfo)
}

func renderError(target dom.Element, err error) {
	target.SetInnerHTML(err.Error())
}
