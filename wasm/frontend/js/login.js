(function () {
    const providersNode = document.getElementById("providers");
    const redirectTarget = "wasm_exec.html";

    function redirectToApp() {
        window.location.assign(redirectTarget);
    }

    const providers = new window.LoginProviders(providersNode, redirectToApp);

    async function bootstrap() {
        providersNode.hidden = true;
        if (window.AuthToken && await window.AuthToken.validateStoredToken()) {
            redirectToApp();
            return;
        }
        providers.showDeprecatedLogin();
    }

    bootstrap();
})();