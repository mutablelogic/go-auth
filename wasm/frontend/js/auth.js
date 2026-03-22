(function () {
    class AuthAPI {
        constructor(basePath) {
            this.basePath = basePath;
        }

        async request(path, options) {
            const response = await fetch(this.basePath + path, {
                credentials: "same-origin",
                ...options,
            });

            const text = await response.text();
            let data = null;

            if (text) {
                try {
                    data = JSON.parse(text);
                } catch {
                    data = text;
                }
            }

            if (!response.ok) {
                const detail = typeof data === "string" ? data : JSON.stringify(data);
                throw new Error(detail || response.status + " " + response.statusText);
            }

            return data;
        }

        async fetchConfig() {
            return this.request("/config");
        }

        async fetchProviders() {
            return this.fetchConfig();
        }

        async loginWithOAuthToken(provider, token) {
            return this.request("/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    provider,
                    token,
                })
            });
        }

        async loginWithCredentials(email, meta) {
            const body = { email };
            if (meta && Object.keys(meta).length > 0) {
                body.meta = meta;
            }

            return this.request("/credentials", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(body)
            });
        }

        async fetchUserInfo(token) {
            return this.request("/userinfo", {
                method: "GET",
                headers: {
                    Authorization: "Bearer " + token
                }
            });
        }

        async refreshToken(token) {
            return this.request("/refresh", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    token,
                })
            });
        }

        async revokeToken(token) {
            await this.request("/revoke", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    token,
                })
            });

            return true;
        }

        async validateToken(token) {
            await this.fetchUserInfo(token);
            return true;
        }
    }

    window.AuthAPI = new AuthAPI("/auth");
})();