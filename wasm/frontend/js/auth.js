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
            throw new Error("Deprecated browser login config path: this page no longer uses /auth/config.");
        }

        async fetchProviders() {
            throw new Error("Deprecated browser login provider path: use the authorization-code flow instead.");
        }

        async loginWithOAuthToken(provider, token) {
            void provider;
            void token;
            throw new Error("Deprecated client login path: use the browser authorization-code flow instead of /auth/login.");
        }

        async loginWithCredentials(email, meta) {
            void email;
            void meta;
            throw new Error("Deprecated client login path: use the browser authorization-code flow instead of /auth/credentials.");
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
            const body = new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: token,
            });

            return this.request("/code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body,
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