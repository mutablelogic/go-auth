(function () {
    class AuthTokenStore {
        constructor(storageKey) {
            this.storageKey = storageKey;
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

            window.localStorage.setItem(this.storageKey, token);
        }

        clearStoredToken() {
            try {
                window.localStorage.removeItem(this.storageKey);
            } catch {
                // Ignore storage cleanup failures.
            }
        }

        async validateStoredToken() {
            const token = this.getStoredToken();
            if (!token) {
                return false;
            }

            try {
                if (!window.AuthAPI) {
                    throw new Error("missing auth api");
                }

                await window.AuthAPI.validateToken(token);
                return true;
            } catch {
                this.clearStoredToken();
                return false;
            }
        }
    }

    window.AuthToken = new AuthTokenStore("auth_token");
})();