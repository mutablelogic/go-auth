package main

import (
	"encoding/json"
	"strings"

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
	currentTheme := carbon.ThemeG90
	menuItemSize := carbon.SizeSmall
	menuIconSize := carbon.IconSize20
	var themeItems []mvc.View
	themeSelector := carbon.OverflowMenu(
		mvc.WithID("theme-selector"),
		carbon.Icon(carbon.IconSettings, carbon.With(menuIconSize)),
	).SetLabel("Theme selector")
	themeWhite := newThemeMenuItem("White", carbon.ThemeWhite, &currentTheme, &themeItems)
	themeGray10 := newThemeMenuItem("Gray 10", carbon.ThemeG10, &currentTheme, &themeItems)
	themeGray90 := newThemeMenuItem("Gray 90", carbon.ThemeG90, &currentTheme, &themeItems)
	themeGray100 := newThemeMenuItem("Gray 100", carbon.ThemeG100, &currentTheme, &themeItems)
	themeItems = []mvc.View{themeWhite, themeGray10, themeGray90, themeGray100}
	for _, item := range themeItems {
		item.Apply(carbon.With(menuItemSize)...)
	}
	updateThemeMenuSelection(themeItems, currentTheme)
	themeSelector.Content(
		themeWhite,
		themeGray10,
		themeGray90,
		themeGray100,
	)
	userSummary := carbon.OverflowMenuItem("Loading session...").SetEnabled(false)
	userSummary.Apply(carbon.With(menuItemSize)...)
	userDetail := carbon.OverflowMenuItem("Fetching current user info.").SetEnabled(false)
	userDetail.Apply(carbon.With(menuItemSize)...)
	refreshUser := carbon.OverflowMenuItem("Refresh session").SetDivider(true)
	refreshUser.Apply(carbon.With(menuItemSize)...)
	refreshUser.AddEventListener(carbon.EventOverflowMenuItemClick, func(dom.Event) {
		loadUserMenu(userSummary, userDetail)
	})
	logout := carbon.OverflowMenuItem("Logout").SetDanger(true)
	logout.Apply(carbon.With(menuItemSize)...)
	logout.AddEventListener(carbon.EventOverflowMenuItemClick, func(dom.Event) {
		frontendAuth.Logout(func() {
			js.Global().Get("location").Set("href", "/")
		}, func(err error) {
			js.Global().Get("console").Call("error", err.Error())
		})
	})
	userInfo := carbon.OverflowMenu(
		mvc.WithID("user-info"),
		carbon.Icon(carbon.IconUserAvatar, carbon.With(menuIconSize)),
	).SetLabel("User information")
	userInfo.Content(userSummary, userDetail, refreshUser, logout)
	loadUserMenu(userSummary, userDetail)
	headerGlobal := carbon.HeaderNavGlobal(themeSelector, userInfo)
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
		carbon.Header(
			headerNavItem,
			headerGlobal,
		).SetLabel("/wasm_exec.html", "Go Auth", "Console").SetActive(headerNavItem),
		sideNav,
		carbon.Section(
			router,
		),
	}
}

func newThemeMenuItem(label string, theme carbon.Attr, current *carbon.Attr, items *[]mvc.View) mvc.View {
	item := carbon.OverflowMenuItem().SetValue(string(theme))
	item.AddEventListener(carbon.EventOverflowMenuItemClick, func(dom.Event) {
		*current = theme
		applyTheme(theme)
		updateThemeMenuSelection(*items, theme)
	})
	setThemeMenuItemLabel(item, label, *current == theme)
	return item
}

func updateThemeMenuSelection(items []mvc.View, theme carbon.Attr) {
	for _, item := range items {
		if item == nil {
			continue
		}
		selected := item.Root().GetAttribute("value") == string(theme)
		setThemeMenuItemLabel(item, themeLabel(carbon.Attr(item.Root().GetAttribute("value"))), selected)
	}
}

func setThemeMenuItemLabel(item mvc.View, label string, selected bool) {
	if item == nil {
		return
	}
	root := item.Root()
	root.SetInnerHTML(label)
	if selected {
		root.AppendChild(carbon.Icon(
			carbon.IconCheckmark,
			mvc.WithAttr("slot", "icon"),
			mvc.WithAttr("aria-hidden", "true"),
		).Root())
	}
}

func themeLabel(theme carbon.Attr) string {
	switch theme {
	case carbon.ThemeWhite:
		return "White"
	case carbon.ThemeG10:
		return "Gray 10"
	case carbon.ThemeG90:
		return "Gray 90"
	case carbon.ThemeG100:
		return "Gray 100"
	default:
		return string(theme)
	}
}

func loadUserMenu(summary, detail mvc.View) {
	setMenuItemLabel(summary, "Loading session...")
	setMenuItemLabel(detail, "Fetching current user info.")
	frontendAuth.UserInfo(func(userinfo string) {
		primary, secondary := summarizeUserInfo(userinfo)
		setMenuItemLabel(summary, primary)
		setMenuItemLabel(detail, secondary)
	}, func(err error) {
		setMenuItemLabel(summary, "Session unavailable")
		setMenuItemLabel(detail, err.Error())
	})
}

func setMenuItemLabel(item mvc.View, label string) {
	if item == nil {
		return
	}
	item.Root().SetInnerHTML(label)
}

func applyTheme(theme carbon.Attr) {
	body := js.Global().Get("document").Get("body")
	if body.IsUndefined() || body.IsNull() {
		return
	}
	classList := body.Get("classList")
	for _, candidate := range []carbon.Attr{carbon.ThemeWhite, carbon.ThemeG10, carbon.ThemeG90, carbon.ThemeG100} {
		classList.Call("remove", carbon.ClassForTheme(candidate))
	}
	classList.Call("add", carbon.ClassForTheme(theme))
}

func summarizeUserInfo(userinfo string) (string, string) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(userinfo), &payload); err != nil {
		compact := strings.TrimSpace(userinfo)
		if compact == "" {
			return "User details unavailable", "No session fields returned."
		}
		return "Signed in", compact
	}
	primary := firstNonEmpty(payload, "name", "preferred_username", "email", "sub")
	secondary := firstNonEmpty(payload, "email", "preferred_username", "sub")
	if primary == "" {
		primary = "Signed in"
	}
	if secondary == "" || secondary == primary {
		secondary = "Session is active."
	}
	return primary, secondary
}

func firstNonEmpty(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			if text := strings.TrimSpace(strings.Trim(fmtAny(value), `"`)); text != "" {
				return text
			}
		}
	}
	return ""
}

func fmtAny(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func newUsersPage() mvc.View {
	return newPlaceholderPage("Users", "Manage and browse users from this section.")
}

func newPlaceholderPage(titleText, summaryText string) mvc.View {
	return carbon.Page(
		mvc.HTML("DIV",
			carbon.Head(2, titleText),
			carbon.Lead(summaryText),
			carbon.Para("This section is ready for the next Carbon-backed view."),
		),
	)
}
