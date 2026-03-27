(function () {
    class AuthAPI {
        constructor(prefixes) {
            this.prefixes = Array.isArray(prefixes) ? prefixes : [""];
            this.resolvedPrefix = null;
        }

        orderedPrefixes() {
            const unique = [];
            const seen = new Set();
            const prefixes = this.resolvedPrefix === null ? this.prefixes : [this.resolvedPrefix, ...this.prefixes];
            for (const prefix of prefixes) {
                const normalized = prefix || "";
                if (seen.has(normalized)) {
                    continue;
                }
                seen.add(normalized);
                unique.push(normalized);
            }

            return unique;
        }

        endpoint(prefix, scope, path) {
            const normalizedPrefix = prefix || "";
            if (scope === "config") {
                return `${normalizedPrefix}/config`;
            }

            return `${normalizedPrefix}/auth${path}`;
        }

        async parseResponse(response) {
            const text = await response.text();
            if (!text) {
                return null;
            }
            try {
                return JSON.parse(text);
            } catch {
                return text;
            }
        }

        async request(scope, path, options) {
            let lastError = null;
            for (const prefix of this.orderedPrefixes()) {
                const endpoint = this.endpoint(prefix, scope, path);
                const response = await fetch(endpoint, {
                    credentials: "same-origin",
                    ...options,
                });
                const data = await this.parseResponse(response);

                if (response.ok) {
                    this.resolvedPrefix = prefix;
                    return data;
                }
                if (response.status === 404) {
                    lastError = new Error(`404 Not Found: ${endpoint}`);
                    continue;
                }

                const detail = typeof data === "string" ? data : JSON.stringify(data);
                throw new Error(detail || response.status + " " + response.statusText);
            }

            throw lastError || new Error("request failed");
        }

        async fetchConfig() {
            return this.request("config", "", {
                method: "GET",
            });
        }

        authorizationURL(params) {
            const prefix = this.resolvedPrefix === null ? this.prefixes[0] || "" : this.resolvedPrefix;
            const endpoint = this.endpoint(prefix, "auth", "/authorize");
            const uri = new URL(endpoint, window.location.origin);
            for (const [key, value] of Object.entries(params || {})) {
                if (value !== undefined && value !== null && value !== "") {
                    uri.searchParams.set(key, value);
                }
            }

            return uri.toString();
        }

        async exchangeAuthorizationCode(request) {
            return this.request("auth", "/code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(request),
            });
        }

        async fetchUserInfo(token) {
            return this.request("auth", "/userinfo", {
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

            return this.request("auth", "/code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body,
            });
        }

        async revokeToken(token) {
            await this.request("auth", "/revoke", {
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

    window.AuthAPI = new AuthAPI(["/api", ""]);
})();