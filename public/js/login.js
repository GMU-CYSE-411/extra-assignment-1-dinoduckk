(function setupFixationHelper() {
  const params = new URLSearchParams(window.location.search);
  const fixedSession = params.get("sid");

  // This helper is intentionally part of the lab to demonstrate session fixation.
  // The server-side fix rotates the session after login, so this can’t elevate privileges.
  if (fixedSession) {
    document.cookie = `sid=${fixedSession}; path=/`;
  }
})();

// store the CSRF token for the current session.
window.currentCsrfToken = null;

// Helper so other scripts can set/update the token.
function setCsrfToken(token) {
  window.currentCsrfToken = token || null;
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);
  const payload = Object.fromEntries(formData.entries());

  try {
    const result = await api("/api/login", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    // save CSRF token returned by server after successful login.
    if (result && result.csrfToken) {
      setCsrfToken(result.csrfToken);
    }

    writeJson("login-output", result);
  } catch (error) {
    writeJson("login-output", { error: error.message });
  }
});