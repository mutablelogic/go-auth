(function () {
    class AuthTokenStore {
        constructor(storageKey) {
            this.storageKey = storageKey;
            this.userinfoKey = storageKey + "_userinfo";
        }

        decodeTokenClaims(token) {
            if (!token) {
                return null;
            }

            try {
                const parts = token.split(".");
                if (parts.length < 2 || !parts[1]) {
                    return null;
                }

                const payload = parts[1]
                    .replace(/-/g, "+")
                    .replace(/_/g, "/");
                const padded = payload + "=".repeat((4 - (payload.length % 4 || 4)) % 4);
                return JSON.parse(window.atob(padded));
            } catch {
                return null;
            }
        }

        isTokenExpired(token) {
            const claims = this.decodeTokenClaims(token);
            if (!claims || typeof claims.exp !== "number") {
                return false;
            }

            return claims.exp <= Math.floor(Date.now() / 1000);
        }

        getStoredToken() {
            try {
                return window.localStorage.getItem(this.storageKey);
            } catch {
                return null;
            }
        }

        storeToken(token) {
            if (!token) {
                throw new Error("missing local token");
            }

            const current = this.getStoredToken();
            window.localStorage.setItem(this.storageKey, token);
            if (current && current !== token) {
                this.clearCachedUserInfo();
            }
        }

        clearStoredToken() {
            try {
                window.localStorage.removeItem(this.storageKey);
                this.clearCachedUserInfo();
            } catch {
                // Ignore storage cleanup failures.
            }
        }

        getCachedUserInfo(token) {
            try {
                if (this.isTokenExpired(token)) {
                    this.clearCachedUserInfo();
                    return null;
                }

                const raw = window.localStorage.getItem(this.userinfoKey);
                if (!raw) {
                    return null;
                }

                const cached = JSON.parse(raw);
                if (!cached || cached.token !== token) {
                    return null;
                }

                return cached.userinfo || null;
            } catch {
                return null;
            }
        }

        storeCachedUserInfo(token, userinfo) {
            if (!token || !userinfo) {
                return;
            }

            try {
                window.localStorage.setItem(this.userinfoKey, JSON.stringify({ token, userinfo }));
            } catch {
                // Ignore cache write failures.
            }
        }

        clearCachedUserInfo() {
            try {
                window.localStorage.removeItem(this.userinfoKey);
            } catch {
                // Ignore cache cleanup failures.
            }
        }

        async validateStoredToken() {
            const token = this.getStoredToken();
            if (!token) {
                return false;
            }

            if (this.isTokenExpired(token)) {
                this.clearStoredToken();
                return false;
            }

            try {
                if (window.GoAuthBridge && typeof window.GoAuthBridge.validateStoredToken === "function") {
                    return !!(await window.GoAuthBridge.validateStoredToken());
                }

                if (!window.AuthAPI) {
                    throw new Error("missing auth api");
                }

                const userinfo = await window.AuthAPI.fetchUserInfo(token);
                this.storeCachedUserInfo(token, userinfo);
                return true;
            } catch {
                this.clearStoredToken();
                return false;
            }
        }
    }

    window.AuthToken = new AuthTokenStore("auth_token");
})();