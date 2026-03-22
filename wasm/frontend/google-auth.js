(function () {
    class LoginGoogleAuth {
        constructor(onSuccess) {
            this.onSuccess = onSuccess;
            this.googleGISReady = false;
            this.pendingMessage = null;
            this.pendingButton = null;
            this.promptAwaitingCredential = false;
            this.handleCredential = this.handleCredential.bind(this);
        }

        setFeedback(node, message, tone) {
            if (!node) {
                return;
            }

            node.textContent = message || "";
            if (tone) {
                node.dataset.tone = tone;
            } else {
                delete node.dataset.tone;
            }
        }

        formatMoment(message, reason) {
            return reason ? `${message} (${reason}).` : `${message}.`;
        }

        describePromptNotification(notification) {
            if (!notification) {
                return null;
            }

            if (typeof notification.isNotDisplayed === "function" && notification.isNotDisplayed()) {
                const reason = typeof notification.getNotDisplayedReason === "function" ? notification.getNotDisplayedReason() : "not_displayed";
                return this.formatMoment("Google sign-in could not be shown", reason);
            }

            if (typeof notification.isSkippedMoment === "function" && notification.isSkippedMoment()) {
                const reason = typeof notification.getSkippedReason === "function" ? notification.getSkippedReason() : "skipped";
                return this.formatMoment("Google sign-in was skipped", reason);
            }

            if (typeof notification.isDismissedMoment === "function" && notification.isDismissedMoment()) {
                const reason = typeof notification.getDismissedReason === "function" ? notification.getDismissedReason() : "dismissed";
                return this.formatMoment("Google sign-in was dismissed", reason);
            }

            return null;
        }

        setLoading(loading) {
            if (this.pendingButton) {
                this.pendingButton.disabled = loading;
            }
        }

        async handleCredential(response) {
            this.promptAwaitingCredential = false;
            this.setLoading(true);
            this.setFeedback(this.pendingMessage, "Signing in…");

            try {
                const result = await window.AuthAPI.loginWithOAuthToken("oauth", response.credential);
                window.AuthToken.storeToken(result && result.token);
                this.setFeedback(this.pendingMessage, "Signed in", "success");
                this.onSuccess(result);
            } catch (error) {
                this.setFeedback(this.pendingMessage, `Google login failed: ${error.message || error}`, "error");
            } finally {
                this.setLoading(false);
            }
        }

        initialize(clientId) {
            if (!clientId || this.googleGISReady) {
                return;
            }

            const initialize = () => {
                if (!window.google || !window.google.accounts || !window.google.accounts.id) {
                    window.setTimeout(initialize, 100);
                    return;
                }

                window.google.accounts.id.initialize({
                    client_id: clientId,
                    callback: this.handleCredential,
                    auto_select: false,
                    cancel_on_tap_outside: true,
                    use_fedcm_for_prompt: false
                });
                this.googleGISReady = true;
            };

            initialize();
        }

        bindButton(button, output) {
            button.addEventListener("click", () => {
                this.setFeedback(output, "");
                this.pendingMessage = output;
                this.pendingButton = button;
                this.promptAwaitingCredential = true;

                if (!this.googleGISReady || !window.google || !window.google.accounts || !window.google.accounts.id) {
                    this.promptAwaitingCredential = false;
                    this.setFeedback(output, "Google Sign-In is not available.", "error");
                    return;
                }

                this.setLoading(true);
                window.google.accounts.id.prompt((notification) => {
                    if (!this.promptAwaitingCredential) {
                        return;
                    }

                    const message = this.describePromptNotification(notification);
                    if (message) {
                        this.promptAwaitingCredential = false;
                        this.setLoading(false);
                        this.setFeedback(output, message, "error");
                    }
                });
            });
        }
    }

    window.LoginGoogleAuth = LoginGoogleAuth;
})();