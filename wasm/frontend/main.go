package main

import (
	"net/url"

	// Packages
	auth "github.com/djthorpe/go-auth/wasm/frontend/pkg/auth"
	controller "github.com/djthorpe/go-auth/wasm/frontend/pkg/controller"
	view "github.com/djthorpe/go-auth/wasm/frontend/pkg/view"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	browserdom "github.com/djthorpe/go-wasmbuild/pkg/dom"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

const (
	defaultTheme        = carbon.ThemeG90
	defaultMenuItemSize = carbon.SizeSmall
	defaultMenuIconSize = carbon.IconSize20
)

type App struct {
	auth              *auth.Auth
	userController    *controller.UserController
	sessionController *controller.SessionController
	themeController   *controller.ThemeController

	usersPage  *view.UserView
	userPanel  *view.UserPanelView
	groupsPage *view.GroupsView
	scopesPage *view.ScopesView

	themeSelector *view.ThemeMenuView
	userInfo      *view.UserMenuView
	headerNav     *view.HeaderNavView
	sideNav       *view.SideNavView
}

func main() {
	mvc.New(NewApp().Views()...).Run()
}

func NewApp() *App {
	app := &App{
		auth:          auth.New(),
		usersPage:     view.NewUserView(),
		userPanel:     view.NewUserPanelView(),
		groupsPage:    view.NewGroupsView(),
		scopesPage:    view.NewScopesView(),
		themeSelector: view.NewThemeMenuView(defaultTheme, defaultMenuItemSize, defaultMenuIconSize),
		userInfo:      view.NewUserMenuView(defaultMenuItemSize, defaultMenuIconSize),
		sideNav:       view.NewSideNavView(),
	}

	app.userController = controller.NewUserController(apiBaseURL())
	app.sessionController = controller.NewSessionController(app.auth)
	app.themeController = controller.NewThemeController(defaultTheme)

	app.userController.Bind(app.usersPage, app.userPanel)
	app.sessionController.Bind(app.userInfo)
	app.themeController.Bind(app.themeSelector)

	app.headerNav = view.NewHeaderNavView(app.themeSelector, app.userInfo)

	return app
}

func (app *App) Views() []any {
	router := mvc.Router().
		Active(app.sideNav).
		Page("#users", app.usersPage, app.sideNav.Users()).
		Page("#groups", app.groupsPage, app.sideNav.Groups()).
		Page("#scopes", app.scopesPage, app.sideNav.Scopes())

	return []any{
		carbon.With(defaultTheme),
		app.headerNav,
		app.sideNav,
		carbon.Section(
			router,
		),
		app.userPanel,
	}
}

func apiBaseURL() *url.URL {
	href := browserdom.GetWindow().Location().Href()
	if href == "" {
		base, _ := url.Parse("/api")
		return base
	}
	base, err := url.Parse(href)
	if err != nil {
		fallback, _ := url.Parse("/api")
		return fallback
	}
	base.Path = "/api"
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base
}
