async function loadSettings() {
  //no userId parameter; server uses session to choose which settings to load.
  const result = await api(`/api/settings`);
  const settings = result.settings;

  const formUserId = document.getElementById("settings-form-user-id");
  const settingsUserId = document.getElementById("settings-user-id");

  if (formUserId) formUserId.value = settings.userId;
  if (settingsUserId) settingsUserId.value = settings.userId;

  const form = document.getElementById("settings-form");
  form.elements.displayName.value = settings.displayName;
  form.elements.theme.value = settings.theme;
  form.elements.statusMessage.value = settings.statusMessage;
  form.elements.emailOptIn.checked = Boolean(settings.emailOptIn);

  const statusPreview = document.getElementById("status-preview");
  statusPreview.textContent = "";

  //  render preview via text nodes, not innerHTML, to avoid XSS.
  const nameP = document.createElement("p");
  nameP.textContent = settings.displayName;
  statusPreview.appendChild(nameP);

  const statusP = document.createElement("p");
  statusP.textContent = settings.statusMessage;
  statusPreview.appendChild(statusP);

  writeJson("settings-output", settings);
}

(async function bootstrapSettings() {
  try {
    const user = await loadCurrentUser();

    if (!user) {
      writeJson("settings-output", { error: "Please log in first." });
      return;
    }

    await loadSettings();
  } catch (error) {
    writeJson("settings-output", { error: error.message });
  }
})();

//original settings-query-form (for arbitrary userId) is now obsolete,
// since the server enforces that each user can only load their own settings.

document.getElementById("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);
  const payload = {
    // do not send userId; backend uses current session user.
    displayName: formData.get("displayName"),
    theme: formData.get("theme"),
    statusMessage: formData.get("statusMessage"),
    emailOptIn: formData.get("emailOptIn") === "on"
  };

  const result = await api("/api/settings", {
    method: "POST",
    body: JSON.stringify(payload)
  });

  writeJson("settings-output", result);
  await loadSettings();
});

document.getElementById("enable-email").addEventListener("click", async () => {
  const result = await api("/api/settings/toggle-email", {
    method: "POST",
    body: JSON.stringify({ enabled: 1 })
  });
  writeJson("settings-output", result);
  await loadSettings();
});

document.getElementById("disable-email").addEventListener("click", async () => {
  const result = await api("/api/settings/toggle-email", {
    method: "POST",
    body: JSON.stringify({ enabled: 0 })
  });
  writeJson("settings-output", result);
  await loadSettings();
});