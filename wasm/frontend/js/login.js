(function () {
    const providersNode = document.getElementById("providers");
    const statusNode = document.getElementById("status");
    const feedbackNode = document.getElementById("feedback");
    const redirectTarget = "wasm_exec.html";
    const flowStorageKey = "auth.authorization_flow";
    const defaultLoginScope = "openid email profile";

    function redirectToApp() {
        window.location.assign(redirectTarget);
    }

    function setFeedback(message, tone) {
        if (!feedbackNode || !statusNode) {
            return;
        }

        feedbackNode.textContent = message || "";
        feedbackNode.dataset.tone = tone || "info";
        statusNode.hidden = !message;
    }

    function providerTitle(provider) {
        const value = (provider || "").trim();
        if (value === "") {
            return "Provider";
        }
        if (value === "local") {
            return "Local";
        }
        if (value === "google") {
            return "Google";
        }

        return value.charAt(0).toUpperCase() + value.slice(1);
    }

    function providerIcon(provider) {
        if ((provider || "").trim() === "google") {
            return `
                <svg class="provider-icon" viewBox="0 0 24 24" aria-hidden="true">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"></path>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"></path>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"></path>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"></path>
                </svg>`;
        }

        return `
            <svg class="provider-icon" viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="12" cy="8" r="4.5" fill="currentColor"></circle>
                <path d="M4.5 21c.8-4.23 3.3-6.35 7.5-6.35S18.7 16.77 19.5 21" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>
            </svg>`;
    }

    function redirectURL() {
        const uri = new URL(window.location.href);
        uri.search = "";
        uri.hash = "";
        return uri.toString();
    }

    function base64url(bytes) {
        let binary = "";
        for (const byte of bytes) {
            binary += String.fromCharCode(byte);
        }
        return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    function randomToken(size) {
        const bytes = new Uint8Array(size);
        window.crypto.getRandomValues(bytes);
        return base64url(bytes);
    }

    async function sha256base64url(value) {
        const encoded = new TextEncoder().encode(value);
        const digest = await window.crypto.subtle.digest("SHA-256", encoded);
        return base64url(new Uint8Array(digest));
    }

    function loadFlow() {
        try {
            const raw = window.sessionStorage.getItem(flowStorageKey);
            return raw ? JSON.parse(raw) : null;
        } catch {
            return null;
        }
    }

    function storeFlow(flow) {
        window.sessionStorage.setItem(flowStorageKey, JSON.stringify(flow));
    }

    function clearFlow() {
        try {
            window.sessionStorage.removeItem(flowStorageKey);
        } catch {
            // Ignore storage cleanup failures.
        }
    }

    function replaceURLWithoutAuthParams() {
        const uri = new URL(window.location.href);
        uri.searchParams.delete("code");
        uri.searchParams.delete("state");
        uri.searchParams.delete("scope");
        uri.searchParams.delete("error");
        uri.searchParams.delete("error_description");
        window.history.replaceState({}, document.title, uri.toString());
    }

    function providerCard(provider) {
        const section = document.createElement("section");
        section.className = "provider";

        const button = document.createElement("button");
        button.type = "button";
        button.className = `provider-button ${provider === "local" ? "local" : ""}`.trim();
        button.innerHTML = `${providerIcon(provider)}<span class="provider-label">${providerTitle(provider)} Login</span>`;
        button.addEventListener("click", async () => {
            try {
                button.disabled = true;
                setFeedback(`Starting ${providerTitle(provider)} sign-in...`, "info");

                const state = randomToken(32);
                const nonce = randomToken(32);
                const codeVerifier = randomToken(48);
                const codeChallenge = await sha256base64url(codeVerifier);
                const currentRedirect = redirectURL();
                storeFlow({
                    provider,
                    state,
                    nonce,
                    codeVerifier,
                    redirectURL: currentRedirect,
                });

                window.location.assign(window.AuthAPI.authorizationURL({
                    provider,
                    redirect_uri: currentRedirect,
                    response_type: "code",
                    state,
                    nonce,
                    scope: defaultLoginScope,
                    code_challenge: codeChallenge,
                    code_challenge_method: "S256",
                }));
            } catch (error) {
                button.disabled = false;
                setFeedback(`Unable to start sign-in: ${error.message || error}`, "error");
            }
        });
        section.appendChild(button);

        return section;
    }

    async function renderProviders() {
        if (!providersNode) {
            return;
        }

        setFeedback("Loading providers...", "info");
        const config = await window.AuthAPI.fetchConfig();
        const entries = Object.entries(config || {}).sort(([left], [right]) => left.localeCompare(right));
        if (entries.length === 0) {
            throw new Error("No providers are configured.");
        }

        providersNode.replaceChildren(...entries.map(([provider]) => providerCard(provider)));
        providersNode.hidden = false;
        setFeedback("", "info");
    }

    async function handleCallback() {
        const uri = new URL(window.location.href);
        const code = (uri.searchParams.get("code") || "").trim();
        const state = (uri.searchParams.get("state") || "").trim();
        const error = (uri.searchParams.get("error") || "").trim();
        const errorDescription = (uri.searchParams.get("error_description") || "").trim();
        if (!code && !error) {
            return false;
        }

        const flow = loadFlow();
        if (!flow) {
            replaceURLWithoutAuthParams();
            throw new Error("Missing stored authorization flow state.");
        }
        if (state === "" || state !== flow.state) {
            clearFlow();
            replaceURLWithoutAuthParams();
            throw new Error("Authorization callback state mismatch.");
        }
        if (error) {
            clearFlow();
            replaceURLWithoutAuthParams();
            throw new Error(errorDescription ? `${error}: ${errorDescription}` : error);
        }

        setFeedback("Completing sign-in...", "info");
        const response = await window.AuthAPI.exchangeAuthorizationCode({
            provider: flow.provider,
            code,
            redirect_uri: flow.redirectURL,
            code_verifier: flow.codeVerifier,
            nonce: flow.nonce,
        });
        clearFlow();
        replaceURLWithoutAuthParams();
        window.AuthToken.storeToken(response && response.token);
        redirectToApp();
        return true;
    }

    async function bootstrap() {
        if (providersNode) {
            providersNode.hidden = true;
        }
        if (statusNode) {
            statusNode.hidden = true;
        }

        if (window.AuthToken && await window.AuthToken.validateStoredToken()) {
            redirectToApp();
            return;
        }

        try {
            if (await handleCallback()) {
                return;
            }
            await renderProviders();
        } catch (error) {
            if (providersNode) {
                providersNode.hidden = true;
            }
            setFeedback(error.message || String(error), "error");
        }
    }

    bootstrap();
})();