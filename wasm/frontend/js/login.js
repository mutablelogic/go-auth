(function () {
    const providersNode = document.getElementById("providers");
    const redirectTarget = "wasm_exec.html";

    function redirectToApp() {
        window.location.assign(redirectTarget);
    }

    const providers = new window.LoginProviders(providersNode, redirectToApp);
    const googleAuth = new window.LoginGoogleAuth(redirectToApp);

    async function loadProviders() {
        providers.clear();

        try {
            const config = await window.AuthAPI.fetchProviders();

            if (config.google && config.google.client_id) {
                googleAuth.initialize(config.google.client_id);
                providers.showGoogle(googleAuth);
            }

            if (config.local) {
                providers.showLocal(config.local);
            }
        } catch (error) {
            providers.showConfigError(error);
        }
    }

    async function bootstrap() {
        providersNode.hidden = true;
        if (window.AuthToken && await window.AuthToken.validateStoredToken()) {
            redirectToApp();
            return;
        }
        await loadProviders();
    }

    bootstrap();
})();