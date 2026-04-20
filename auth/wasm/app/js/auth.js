function trimTrailingSlash(value) {
    return value.replace(/\/+$/, "");
}

function normalizeBaseURL(input) {
    const base = String(input ?? "").trim();
    if (!base) {
        throw new Error("auth provider base path is required");
    }

    if (typeof window === "undefined" || typeof window.location === "undefined") {
        throw new Error("window.location is required for browser auth provider URLs");
    }

    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(base)) {
        return trimTrailingSlash(base);
    }

    const resolved = base.startsWith("/")
        ? new URL(base, window.location.origin)
        : new URL(base, window.location.href);

    return trimTrailingSlash(resolved.toString());
}

function joinURL(base, path) {
    return `${trimTrailingSlash(base)}/${String(path ?? "").replace(/^\/+/, "")}`;
}

function toQueryString(params) {
    const query = new URLSearchParams();
    if (!params || typeof params !== "object") {
        return query.toString();
    }

    for (const [key, value] of Object.entries(params)) {
        if (value === undefined || value === null) {
            continue;
        }
        if (Array.isArray(value)) {
            for (const item of value) {
                if (item !== undefined && item !== null) {
                    query.append(key, String(item));
                }
            }
            continue;
        }
        query.set(key, String(value));
    }

    return query.toString();
}

async function readResponse(response) {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        return response.json();
    }
    return response.text();
}

class AuthProvider {
    constructor(base) {
        this.baseURL = normalizeBaseURL(base);
    }

    URL(path) {
        return joinURL(this.baseURL, path);
    }

    async Request(path, init = {}) {
        const response = await fetch(this.URL(path), init);
        if (response.ok) {
            return readResponse(response);
        }

        const body = await readResponse(response);
        const error = new Error(`request failed: ${response.status} ${response.statusText}`);
        error.status = response.status;
        error.statusText = response.statusText;
        error.body = body;
        throw error;
    }

    async Config() {
        return this.Request("config");
    }

    AuthorizeURL(params = {}) {
        const query = toQueryString(params);
        const url = this.URL("auth/authorize");
        return query ? `${url}?${query}` : url;
    }

    async Exchange(body, init = {}) {
        return this.Request("auth/code", {
            method: "POST",
            headers: {
                "content-type": "application/json",
                ...(init.headers || {}),
            },
            body: JSON.stringify(body ?? {}),
            ...init,
        });
    }

    async Refresh(token, init = {}) {
        return this.Exchange({
            grant_type: "refresh_token",
            refresh_token: token,
        }, init);
    }

    async Revoke(tokenOrBody, init = {}) {
        const body = typeof tokenOrBody === "string"
            ? { token: tokenOrBody }
            : (tokenOrBody || {});

        return this.Request("auth/revoke", {
            method: "POST",
            headers: {
                "content-type": "application/json",
                ...(init.headers || {}),
            },
            body: JSON.stringify(body),
            ...init,
        });
    }

    async UserInfo(token, init = {}) {
        return this.Request("auth/userinfo", {
            headers: {
                ...(token ? { authorization: `Bearer ${token}` } : {}),
                ...(init.headers || {}),
            },
            ...init,
        });
    }

    async OIDCConfig() {
        return this.Request(".well-known/openid-configuration");
    }

    async JWKS() {
        return this.Request(".well-known/jwks.json");
    }

    async ProtectedResource() {
        return this.Request(".well-known/oauth-protected-resource");
    }
}

function NewAuthProvider(base) {
    return new AuthProvider(base);
}

globalThis.AuthProvider = AuthProvider;
globalThis.NewAuthProvider = NewAuthProvider;
