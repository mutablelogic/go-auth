package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const authConfigPath = "/auth/config"

func (c *Client) authError(err error) error {
	return err
}

func authConfigReference(requestHeader, responseHeader http.Header, requestURL *url.URL) string {
	for _, header := range []http.Header{requestHeader, responseHeader} {
		if ref := authConfigHeader(header); ref != "" {
			return ref
		}
	}
	if requestURL == nil {
		return ""
	}
	path := strings.TrimRight(requestURL.Path, "/")
	if path == "" {
		path = "/"
	}
	if path == authConfigPath {
		return fmt.Sprintf("auth config request: %s", requestURL.String())
	}
	return ""
}

func authConfigHeader(header http.Header) string {
	if header == nil {
		return ""
	}
	for _, key := range []string{"Link", "X-OAuth-Config", "X-Auth-Config", "X-OIDC-Config", "X-OpenID-Configuration"} {
		if value := strings.TrimSpace(header.Get(key)); value != "" {
			return fmt.Sprintf("%s: %s", key, value)
		}
	}
	return ""
}
