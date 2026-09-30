/**
 * EDABIP Authentication Demo Application Script
 * Orchestrates Signup -> OTP Verification -> Login -> Dashboard Flow
 */

document.addEventListener("DOMContentLoaded", () => {
    // Current User & Flow State
    let state = {
        email: "",
        otpCooldownInterval: null,
        cooldownRemaining: 0,
        user: null
    };

    // UI Elements
    const views = {
        signup: document.getElementById("view-signup"),
        otp: document.getElementById("view-otp"),
        login: document.getElementById("view-login"),
        dashboard: document.getElementById("view-dashboard")
    };

    const steps = {
        step1: document.getElementById("step-node-1"),
        step2: document.getElementById("step-node-2"),
        step3: document.getElementById("step-node-3")
    };

    const alertBanner = document.getElementById("alert-banner");
    const signupForm = document.getElementById("signup-form");
    const otpForm = document.getElementById("otp-form");
    const loginForm = document.getElementById("login-form");
    const otpTargetEmail = document.getElementById("otp-target-email");
    const btnResend = document.getElementById("btn-resend");
    const resendTimerText = document.getElementById("resend-timer-text");
    const btnLogout = document.getElementById("btn-logout");

    // Navigation Links
    document.getElementById("link-to-login").addEventListener("click", (e) => {
        e.preventDefault();
        showView("login");
    });

    document.getElementById("link-to-signup").addEventListener("click", (e) => {
        e.preventDefault();
        showView("signup");
    });

    document.getElementById("link-back-signup").addEventListener("click", (e) => {
        e.preventDefault();
        showView("signup");
    });

    btnLogout.addEventListener("click", () => {
        state.user = null;
        showAlert("You have been signed out.", "success");
        showView("login");
    });

    // View Management
    function showView(viewName) {
        clearAlert();
        clearAllFieldErrors();

        Object.keys(views).forEach(key => {
            views[key].classList.toggle("hidden", key !== viewName);
        });

        // Update Stepper
        steps.step1.classList.remove("active");
        steps.step2.classList.remove("active");
        steps.step3.classList.remove("active");

        if (viewName === "signup") {
            steps.step1.classList.add("active");
        } else if (viewName === "otp") {
            steps.step2.classList.add("active");
            if (state.email) {
                otpTargetEmail.textContent = state.email;
            }
        } else if (viewName === "login" || viewName === "dashboard") {
            steps.step3.classList.add("active");
        }
    }

    // Alerts & Error Rendering
    function showAlert(message, type = "error") {
        alertBanner.textContent = message;
        alertBanner.className = `alert-banner alert-${type}`;
        alertBanner.classList.remove("hidden");
    }

    function clearAlert() {
        alertBanner.textContent = "";
        alertBanner.className = "alert-banner hidden";
    }

    function clearAllFieldErrors() {
        document.querySelectorAll(".field-error").forEach(el => el.textContent = "");
        document.querySelectorAll("input").forEach(el => el.classList.remove("is-invalid"));
    }

    function setFieldError(field, message) {
        if (!field) return;
        const errEl = document.getElementById(`error-${field}`);
        const inputEl = document.getElementById(field);
        if (errEl) errEl.textContent = message;
        if (inputEl) inputEl.classList.add("is-invalid");
    }

    // Handle Signup Submission
    signupForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        clearAlert();
        clearAllFieldErrors();

        const formData = {
            first_name: document.getElementById("first_name").value.trim(),
            last_name: document.getElementById("last_name").value.trim(),
            email: document.getElementById("email").value.trim(),
            password: document.getElementById("password").value,
            confirm_password: document.getElementById("confirm_password").value
        };

        const submitBtn = document.getElementById("btn-signup");
        submitBtn.disabled = true;
        submitBtn.textContent = "Creating Account...";

        try {
            const res = await fetch("/auth/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(formData)
            });

            const data = await res.json();

            if (!res.ok || !data.success) {
                handleApiError(data, res.status);
            } else {
                state.email = formData.email;
                showAlert(data.message || "Account created! Please verify your email.", "success");
                showView("otp");
                startCooldown(60); // 60s cooldown for resend
            }
        } catch (err) {
            showAlert("Network error connecting to backend API.", "error");
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Create Account";
        }
    });

    // Handle OTP Verification
    otpForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        clearAlert();
        clearAllFieldErrors();

        const otpVal = document.getElementById("otp").value.trim();
        if (!otpVal) {
            setFieldError("otp", "Please enter the 6-digit OTP code.");
            return;
        }

        const verifyBtn = document.getElementById("btn-verify");
        verifyBtn.disabled = true;
        verifyBtn.textContent = "Verifying...";

        try {
            const res = await fetch("/auth/verify-otp", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email: state.email,
                    otp: otpVal
                })
            });

            const data = await res.json();

            if (!res.ok || !data.success) {
                handleApiError(data, res.status);
            } else {
                showAlert(data.message || "Email verified successfully! Please log in.", "success");
                document.getElementById("login-email").value = state.email;
                showView("login");
            }
        } catch (err) {
            showAlert("Network error connecting to backend API.", "error");
        } finally {
            verifyBtn.disabled = false;
            verifyBtn.textContent = "Verify Email";
        }
    });

    // Handle Resend OTP
    btnResend.addEventListener("click", async () => {
        if (!state.email) {
            showAlert("Email is missing. Please sign up again.", "error");
            return;
        }

        clearAlert();
        clearAllFieldErrors();
        btnResend.disabled = true;
        btnResend.textContent = "Sending...";

        try {
            const res = await fetch("/auth/resend-otp", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: state.email })
            });

            const data = await res.json();

            if (!res.ok || !data.success) {
                handleApiError(data, res.status);
                // If cooldown error returned with seconds, sync cooldown
                if (data.data && data.data.retry_after_seconds) {
                    startCooldown(data.data.retry_after_seconds);
                }
            } else {
                showAlert(data.message || "A new verification code has been dispatched.", "success");
                startCooldown(60);
            }
        } catch (err) {
            showAlert("Network error connecting to backend API.", "error");
        } finally {
            if (state.cooldownRemaining <= 0) {
                btnResend.disabled = false;
                btnResend.textContent = "Resend OTP";
            }
        }
    });

    // Handle Login Submission
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        clearAlert();
        clearAllFieldErrors();

        const formData = {
            email: document.getElementById("login-email").value.trim(),
            password: document.getElementById("login-password").value
        };

        const loginBtn = document.getElementById("btn-login");
        loginBtn.disabled = true;
        loginBtn.textContent = "Signing In...";

        try {
            const res = await fetch("/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(formData)
            });

            const data = await res.json();

            if (!res.ok || !data.success) {
                if (data.error && data.error.code === "EMAIL_NOT_VERIFIED") {
                    state.email = formData.email;
                    showAlert(data.error.message, "error");
                    showView("otp");
                } else {
                    handleApiError(data, res.status, "login-");
                }
            } else {
                state.user = data.data.user;
                populateDashboard(state.user);
                showView("dashboard");
            }
        } catch (err) {
            showAlert("Network error connecting to backend API.", "error");
        } finally {
            loginBtn.disabled = false;
            loginBtn.textContent = "Sign In";
        }
    });

    function populateDashboard(user) {
        document.getElementById("dash-user-id").textContent = `#${user.id}`;
        document.getElementById("dash-user-name").textContent = `${user.first_name} ${user.last_name}`;
        document.getElementById("dash-user-email").textContent = user.email;
    }

    function handleApiError(data, statusCode, prefix = "") {
        if (data.error) {
            const { message, field, code } = data.error;
            if (field) {
                setFieldError(`${prefix}${field}`, message);
            }
            showAlert(`[${code}] ${message}`, "error");
        } else {
            showAlert(`Request failed with status ${statusCode}.`, "error");
        }
    }

    function startCooldown(seconds) {
        if (state.otpCooldownInterval) {
            clearInterval(state.otpCooldownInterval);
        }
        state.cooldownRemaining = seconds;
        btnResend.disabled = true;
        resendTimerText.classList.remove("hidden");

        const updateTimer = () => {
            if (state.cooldownRemaining > 0) {
                btnResend.textContent = `Resend OTP (${state.cooldownRemaining}s)`;
                resendTimerText.textContent = `You can request another code in ${state.cooldownRemaining} seconds.`;
                state.cooldownRemaining--;
            } else {
                clearInterval(state.otpCooldownInterval);
                btnResend.disabled = false;
                btnResend.textContent = "Resend OTP";
                resendTimerText.classList.add("hidden");
            }
        };

        updateTimer();
        state.otpCooldownInterval = setInterval(updateTimer, 1000);
    }
});
