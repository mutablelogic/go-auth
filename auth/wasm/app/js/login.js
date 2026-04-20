const AUTH_SERVER_BASE = "/api";
const PENDING_AUTH_KEY = "auth.pending";
const TOKEN_RESPONSE_KEY = "auth.tokens";
const DEFAULT_LOGIN_SCOPE = "openid email profile";

function encodeBase64URL(bytes) {
    let text = "";
    for (const byte of bytes) {
        text += String.fromCharCode(byte);
    }

    return btoa(text)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

function randomString(size = 32) {
    const bytes = new Uint8Array(size);
    crypto.getRandomValues(bytes);
    return encodeBase64URL(bytes);
}

async function sha256Base64URL(value) {
    const bytes = new TextEncoder().encode(String(value ?? ""));
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return encodeBase64URL(new Uint8Array(digest));
}

function redirectURL() {
    return `${window.location.origin}${window.location.pathname}`;
}

function readPendingAuth() {
    const raw = sessionStorage.getItem(PENDING_AUTH_KEY);
    return raw ? JSON.parse(raw) : null;
}

function writePendingAuth(value) {
    sessionStorage.setItem(PENDING_AUTH_KEY, JSON.stringify(value));
}

function clearPendingAuth() {
    sessionStorage.removeItem(PENDING_AUTH_KEY);
}

function readTokens() {
    const raw = localStorage.getItem(TOKEN_RESPONSE_KEY);
    return raw ? JSON.parse(raw) : null;
}

function writeTokens(tokens) {
    localStorage.setItem(TOKEN_RESPONSE_KEY, JSON.stringify(tokens));
}

function clearTokens() {
    localStorage.removeItem(TOKEN_RESPONSE_KEY);
}

function setAuthStatus(value) {
    document.getElementById("auth-status").textContent = value;
}

function setProviderStatus(value) {
    document.getElementById("provider-status").textContent = value;
}

function setButtonState(id, enabled) {
    document.getElementById(id).disabled = !enabled;
}

function setButtonHidden(id, hidden) {
    document.getElementById(id).hidden = hidden;
}

function setProviderHeading(value) {
    const heading = document.getElementById("provider-heading");
    const text = String(value ?? "").trim();
    heading.textContent = text;
    heading.hidden = text === "";
}

function clearCallbackQuery() {
    const url = new URL(window.location.href);
    url.search = "";
    window.history.replaceState({}, document.title, url.toString());
}

function formatError(error) {
    return error && error.body
        ? JSON.stringify(error.body, null, 2)
        : (error && error.message ? error.message : String(error));
}

function revokeTokenFrom(tokens) {
    if (!tokens || typeof tokens !== "object") {
        return "";
    }

    return tokens.refresh_token || tokens.access_token || "";
}

function describeUser(userInfo) {
    if (!userInfo || typeof userInfo !== "object") {
        return "current user";
    }

    return userInfo.name || userInfo.email || userInfo.sub || "current user";
}

function setLoggedOutState(providers) {
    const providerList = Array.isArray(providers) ? providers : [];
    const hasLocal = providerList.includes("local");
    const hasGoogle = providerList.includes("google");

    setProviderHeading("");
    setButtonHidden("login-local", !hasLocal);
    setButtonHidden("login-google", !hasGoogle);
    setButtonHidden("refresh-session", true);
    setButtonHidden("revoke-session", true);
    setButtonState("login-local", hasLocal);
    setButtonState("login-google", hasGoogle);
    setButtonState("refresh-session", false);
    setButtonState("revoke-session", false);
    setProviderStatus("");
}

function setLoggedInState(userInfo, tokens) {
    setProviderHeading("");
    setButtonHidden("login-local", true);
    setButtonHidden("login-google", true);
    setButtonHidden("refresh-session", !(tokens && tokens.refresh_token));
    setButtonHidden("revoke-session", false);
    setButtonState("refresh-session", !!(tokens && tokens.refresh_token));
    setButtonState("revoke-session", true);
    setProviderStatus("");
}

async function showUserInfo(authProvider, tokens) {
    if (!tokens || !tokens.access_token) {
        throw new Error("Missing stored access token.");
    }

    const userInfo = await authProvider.UserInfo(tokens.access_token);
    setAuthStatus(JSON.stringify(userInfo, null, 2));
    setLoggedInState(userInfo, tokens);
    return userInfo;
}

async function restoreSession(authProvider, providers) {
    const tokens = readTokens();
    if (!tokens) {
        setLoggedOutState(providers);
        setAuthStatus("Waiting for login.");
        return false;
    }

    try {
        await showUserInfo(authProvider, tokens);
        return true;
    } catch (error) {
        clearTokens();
        setLoggedOutState(providers);
        setAuthStatus(`Stored session is no longer valid. ${formatError(error)}`);
        return false;
    }
}

async function beginLogin(authProvider, providerKey) {
    const state = randomString(24);
    const nonce = randomString(24);
    const codeVerifier = randomString(48);
    const loginRedirectURL = redirectURL();
    const codeChallenge = await sha256Base64URL(codeVerifier);

    writePendingAuth({
        provider: providerKey,
        state,
        nonce,
        codeVerifier,
        redirectURL: loginRedirectURL,
    });

    window.location.assign(authProvider.AuthorizeURL({
        provider: providerKey,
        redirect_uri: loginRedirectURL,
        state,
        nonce,
        scope: DEFAULT_LOGIN_SCOPE,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
    }));
}

async function handleCallback(authProvider) {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const error = params.get("error");
    const errorDescription = params.get("error_description");

    if (!code && !error) {
        return false;
    }

    const pending = readPendingAuth();
    if (!pending) {
        setAuthStatus("Missing pending login state.");
        clearCallbackQuery();
        return false;
    }

    if (error) {
        clearPendingAuth();
        setAuthStatus(`Login failed: ${errorDescription || error}`);
        clearCallbackQuery();
        return false;
    }

    if (pending.state !== state) {
        clearPendingAuth();
        setAuthStatus("Login failed: state mismatch.");
        clearCallbackQuery();
        return false;
    }

    setAuthStatus(`Exchanging authorization code for ${pending.provider}...`);

    const tokens = await authProvider.Exchange({
        grant_type: "authorization_code",
        provider: pending.provider,
        code,
        redirect_uri: pending.redirectURL,
        code_verifier: pending.codeVerifier,
        nonce: pending.nonce,
    });

    writeTokens(tokens);
    clearPendingAuth();
    clearCallbackQuery();

    await showUserInfo(authProvider, tokens);
    return true;
}

document.addEventListener("DOMContentLoaded", async () => {
    const authProvider = NewAuthProvider(AUTH_SERVER_BASE);
    let providers = [];

    document.getElementById("refresh-session").addEventListener("click", async () => {
        try {
            const tokens = readTokens();
            const refreshToken = tokens && tokens.refresh_token;
            if (!refreshToken) {
                throw new Error("Missing stored refresh token.");
            }

            setButtonState("refresh-session", false);
            const refreshedTokens = await authProvider.Refresh(refreshToken);
            writeTokens(refreshedTokens);
            await showUserInfo(authProvider, refreshedTokens);
        } catch (error) {
            clearTokens();
            setLoggedOutState(providers);
            setAuthStatus(formatError(error));
        } finally {
            const refreshButton = document.getElementById("refresh-session");
            if (!refreshButton.hidden) {
                setButtonState("refresh-session", true);
            }
        }
    });

    document.getElementById("revoke-session").addEventListener("click", async () => {
        try {
            const tokens = readTokens();
            const token = revokeTokenFrom(tokens);
            if (!token) {
                throw new Error("Missing stored token to revoke.");
            }

            setAuthStatus("Revoking session...");
            await authProvider.Revoke(token);
            clearTokens();
            clearPendingAuth();
            setLoggedOutState(providers);
            setAuthStatus("Session revoked.");
        } catch (error) {
            setAuthStatus(formatError(error));
        }
    });

    try {
        const config = await authProvider.Config();
        providers = Object.keys(config || {});
    } catch (error) {
        setProviderStatus("Unable to load providers.");
        setAuthStatus(formatError(error));
        return;
    }

    document.getElementById("login-local").addEventListener("click", () => {
        beginLogin(authProvider, "local").catch((error) => {
            setAuthStatus(formatError(error));
        });
    });

    document.getElementById("login-google").addEventListener("click", () => {
        beginLogin(authProvider, "google").catch((error) => {
            setAuthStatus(formatError(error));
        });
    });

    try {
        const handledCallback = await handleCallback(authProvider);
        if (!handledCallback) {
            await restoreSession(authProvider, providers);
        }
    } catch (error) {
        setAuthStatus(formatError(error));
    }
});