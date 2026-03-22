(function () {
    class LoginProviders {
        constructor(rootNode) {
            this.rootNode = rootNode;
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

        clear() {
            this.rootNode.replaceChildren();
            this.rootNode.hidden = false;
        }

        createProvider(title, className) {
            const section = document.createElement("section");
            section.className = className ? `provider stack ${className}` : "provider stack";

            const heading = document.createElement("h2");
            heading.textContent = title;
            section.appendChild(heading);

            return section;
        }

        showGoogle(googleAuth) {
            const section = this.createProvider("Google", "google-provider");
            const button = document.createElement("button");
            button.type = "button";
            button.className = "google";
            button.innerHTML = `
                <svg class="provider-icon" viewBox="0 0 24 24" aria-hidden="true">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"></path>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"></path>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"></path>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"></path>
                </svg>
                <span>Continue with Google</span>
            `;

            const output = document.createElement("div");
            output.className = "feedback";

            section.replaceChildren(button, output);
            this.rootNode.appendChild(section);
            googleAuth.bindButton(button, output);
        }

        showLocal() {
            const section = this.createProvider("Local", "local-provider");
            const form = document.createElement("form");
            form.className = "local-form";

            const label = document.createElement("label");
            label.setAttribute("for", "local-email");
            label.textContent = "Email";
            form.appendChild(label);

            const input = document.createElement("input");
            input.id = "local-email";
            input.type = "email";
            input.name = "email";
            input.placeholder = "you@example.com";
            input.autocomplete = "email";
            input.required = true;
            form.appendChild(input);

            const button = document.createElement("button");
            button.type = "submit";
            button.className = "secondary";
            button.textContent = "Continue";
            form.appendChild(button);

            const output = document.createElement("div");
            output.className = "feedback";
            form.appendChild(output);

            form.addEventListener("submit", (event) => {
                event.preventDefault();
                this.setFeedback(output, `Local is not wired yet: ${input.value.trim()}`, "error");
            });

            section.appendChild(form);
            this.rootNode.appendChild(section);
        }

        showConfigError(error) {
            this.clear();

            const section = this.createProvider("Login", "local-provider");
            const message = document.createElement("div");
            message.className = "feedback";
            this.setFeedback(message, `Failed to load config: ${error.message || error}`, "error");
            section.appendChild(message);
            this.rootNode.appendChild(section);
        }
    }

    window.LoginProviders = LoginProviders;
})();