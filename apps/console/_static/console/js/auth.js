(function () {
    "use strict";

    function csrfToken(form) {
        var input = form.querySelector('input[name="csrfmiddlewaretoken"]');
        return input ? input.value : "";
    }

    function textFor(value) {
        if (Array.isArray(value)) {
            return value.map(textFor).filter(Boolean).join(" ");
        }
        if (value && typeof value === "object") {
            return Object.keys(value).map(function (key) {
                return textFor(value[key]);
            }).filter(Boolean).join(" ");
        }
        return typeof value === "string" ? value : "";
    }

    function resetFeedback(form) {
        form.querySelectorAll("[data-error-for]").forEach(function (element) {
            element.textContent = "";
            element.hidden = true;
        });
        ["[data-auth-error]", "[data-auth-status]"].forEach(function (selector) {
            var element = form.querySelector(selector);
            if (element) {
                element.textContent = "";
                element.hidden = true;
            }
        });
    }

    function showFeedback(form, payload, successfulMessage) {
        resetFeedback(form);
        if (successfulMessage) {
            var status = form.querySelector("[data-auth-status]");
            if (status) {
                status.textContent = successfulMessage;
                status.hidden = false;
                status.focus();
            }
            return;
        }

        var source = payload && typeof payload === "object" ? payload : {};
        if (source.detail && typeof source.detail === "object") {
            source = source.detail;
        }
        var unassigned = [];
        Object.keys(source).forEach(function (key) {
            var message = textFor(source[key]);
            var fieldError = form.querySelector('[data-error-for="' + key + '"]');
            if (fieldError && message) {
                fieldError.textContent = message;
                fieldError.hidden = false;
            } else if (message) {
                unassigned.push(message);
            }
        });
        if (!unassigned.length && payload && typeof payload.detail === "string") {
            unassigned.push(payload.detail);
        }
        if (!unassigned.length) {
            unassigned.push("The request could not be completed. Please try again.");
        }
        var error = form.querySelector("[data-auth-error]");
        if (error) {
            error.textContent = unassigned.join(" ");
            error.hidden = false;
            error.focus();
        }
    }

    async function jsonRequest(form, method, payload, browserSessionLogin) {
        var headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken(form)
        };
        if (browserSessionLogin) {
            headers["X-BackupSheep-Session-Login"] = "1";
        }
        var response = await fetch(form.action, {
            method: method,
            credentials: "same-origin",
            headers: headers,
            body: JSON.stringify(payload),
            redirect: "error"
        });
        var body;
        try {
            body = await response.json();
        } catch (error) {
            body = {detail: "The server returned an unreadable response."};
        }
        if (!response.ok) {
            var requestError = new Error("Authentication request failed");
            requestError.payload = body;
            throw requestError;
        }
        return body;
    }

    function values(form, names) {
        var payload = {};
        names.forEach(function (name) {
            var input = form.elements.namedItem(name);
            if (input) {
                payload[name] = input.value;
            }
        });
        return payload;
    }

    async function submitLogin(form) {
        var body = await jsonRequest(
            form,
            "POST",
            values(form, ["email", "password", "auth_multi_factor_token"]),
            true
        );
        if (body.auth_multi_factor) {
            var mfa = form.querySelector("[data-mfa-fields]");
            var input = form.elements.namedItem("auth_multi_factor_token");
            mfa.hidden = false;
            input.required = true;
            input.focus();
            showFeedback(form, null, "Password accepted. Enter your authenticator code to continue.");
            return;
        }
        // Browser session logins intentionally receive no bearer API key.
        window.location.assign(body.next || "/console");
    }

    async function submitResetRequest(form) {
        await jsonRequest(form, "POST", values(form, ["email"]), false);
        form.elements.namedItem("email").value = "";
        showFeedback(
            form,
            null,
            "If an account uses that email address, a password reset link has been sent."
        );
    }

    async function submitNewPassword(form) {
        await jsonRequest(
            form,
            "PATCH",
            values(form, ["password", "password_confirm", "password_token"]),
            false
        );
        form.elements.namedItem("password").value = "";
        form.elements.namedItem("password_confirm").value = "";
        form.querySelector('button[type="submit"]').disabled = true;
        showFeedback(form, null, "Your password has been updated. You can now return to login.");
    }

    document.addEventListener("DOMContentLoaded", function () {
        document.querySelectorAll("[data-dismiss-auth-message]").forEach(function (button) {
            button.addEventListener("click", function () {
                var message = button.closest("[data-auth-message]");
                if (message) {
                    message.remove();
                }
            });
        });

        document.querySelectorAll("form[data-auth-flow]").forEach(function (form) {
            form.addEventListener("submit", async function (event) {
                event.preventDefault();
                if (!form.reportValidity()) {
                    return;
                }
                resetFeedback(form);
                var button = form.querySelector('button[type="submit"]');
                button.disabled = true;
                form.setAttribute("aria-busy", "true");
                var completed = false;
                try {
                    var flow = form.getAttribute("data-auth-flow");
                    if (flow === "login") {
                        await submitLogin(form);
                    } else if (flow === "request-reset") {
                        await submitResetRequest(form);
                    } else if (flow === "set-password") {
                        await submitNewPassword(form);
                    }
                    completed = true;
                } catch (error) {
                    showFeedback(form, error.payload || {}, null);
                } finally {
                    if (form.getAttribute("data-auth-flow") !== "set-password" || !completed) {
                        button.disabled = false;
                    }
                    form.removeAttribute("aria-busy");
                }
            });
        });
    });
}());
