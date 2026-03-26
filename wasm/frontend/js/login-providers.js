(function () {
    class LoginProviders {
        constructor(rootNode, onSuccess) {
            this.rootNode = rootNode;
            this.messageNode = null;
            this.onSuccess = onSuccess;
        }

        setFeedback(node, message, tone) {
            if (!node) {
                return;
            }

            node.textContent = message || "Choose a provider to login";
            node.dataset.tone = tone || "info";
        }

        clear() {
            this.rootNode.replaceChildren(this.feedbackNode());
            this.rootNode.hidden = false;
            this.setFeedback(this.feedbackNode(), "Browser login on this page has been deprecated.", "info");
        }

        showDeprecatedLogin() {
            this.clear();
            this.setFeedback(
                this.feedbackNode(),
                "Browser login here has been removed. Use the manager or auth CLI login flow, or start an authorization-code flow against /auth/authorize.",
                "error"
            );
        }

        createProvider(title, className) {
            const section = document.createElement("section");
            section.className = className ? `provider stack ${className}` : "provider stack";

            const heading = document.createElement("h2");
            heading.textContent = title;
            section.appendChild(heading);

            return section;
        }

        feedbackNode() {
            if (!this.messageNode) {
                this.messageNode = document.createElement("p");
                this.messageNode.className = "feedback";
            }
            return this.messageNode;
        }

        createGoogleButton() {
            const button = document.createElement("cds-button");
            button.type = "button";
            button.kind = "secondary";
            button.size = "lg";
            button.className = "google login-button";

            const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            icon.setAttribute("slot", "icon");
            icon.setAttribute("class", "provider-icon");
            icon.setAttribute("viewBox", "0 0 24 24");
            icon.setAttribute("aria-hidden", "true");
            icon.innerHTML = `
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"></path>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"></path>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"></path>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"></path>
            `;

            button.append(icon, document.createTextNode("Continue with Google"));
            return button;
        }

        showGoogle(googleAuth) {
            const section = this.createProvider("Google", "google-provider");
            const button = this.createGoogleButton();

            section.replaceChildren(button);
            this.rootNode.appendChild(section);
            googleAuth.bindButton(button, this.feedbackNode());
        }

        showLocal() {
            const section = this.createProvider("Local", "local-provider");
            const form = document.createElement("form");
            form.className = "local-form";

            const input = document.createElement("cds-text-input");
            input.id = "local-email";
            input.type = "email";
            input.name = "email";
            input.label = "Email";
            input.placeholder = "you@example.com";
            input.autocomplete = "email";
            input.helperText = "Use the address associated with your account.";
            input.size = "lg";
            input.required = true;
            form.appendChild(input);

            const button = document.createElement("cds-button");
            button.type = "submit";
            button.kind = "primary";
            button.size = "lg";
            button.className = "login-button";
            button.textContent = "Continue";
            form.appendChild(button);

            const submitLocalLogin = () => {
                const email = (input.value || "").trim();
                input.invalid = false;
                input.invalidText = "";

                if (!email) {
                    input.invalid = true;
                    input.invalidText = "Enter an email address to continue.";
                    this.setFeedback(this.feedbackNode(), "Enter an email address to continue.", "error");
                    return;
                }

                button.disabled = true;
                this.setFeedback(this.feedbackNode(), `Signing in as ${email}...`, "info");

                window.AuthAPI.loginWithCredentials(email).then((result) => {
                    window.AuthToken.storeToken(result && result.token);
                    this.setFeedback(this.feedbackNode(), "Signed in", "success");
                    if (typeof this.onSuccess === "function") {
                        this.onSuccess(result);
                    }
                }).catch((error) => {
                    this.setFeedback(this.feedbackNode(), `Local login failed: ${error.message || error}`, "error");
                }).finally(() => {
                    button.disabled = false;
                });
            };

            form.addEventListener("submit", (event) => {
                event.preventDefault();
                submitLocalLogin();
            });

            button.addEventListener("click", (event) => {
                event.preventDefault();
                submitLocalLogin();
            });

            section.appendChild(form);
            this.rootNode.appendChild(section);
        }

        showConfigError(error) {
            this.clear();
            this.setFeedback(this.feedbackNode(), `Failed to load config: ${error.message || error}`, "error");
        }
    }

    window.LoginProviders = LoginProviders;
})();