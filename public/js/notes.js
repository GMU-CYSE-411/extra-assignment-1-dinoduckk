//simple HTML escape to prevent DOM XSS when rendering note content.
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// noteCard escapes all untrusted fields before inserting into HTML.
function noteCard(note) {
  return `
    <article class="note-card">
      <h3>${escapeHtml(note.title)}</h3>
      <p class="note-meta">Owner: ${escapeHtml(note.ownerUsername)} | ID: ${note.id} | Pinned: ${note.pinned}</p>
      <div class="note-body">${escapeHtml(note.body)}</div>
    </article>
  `;
}

async function loadNotes(search) {
  const query = new URLSearchParams();

  if (search) {
    query.set("search", search);
  }

  // no ownerId in query; server uses session user to enforce auth.
  const result = await api(`/api/notes?${query.toString()}`);
  const notesList = document.getElementById("notes-list");
  notesList.innerHTML = result.notes.map(noteCard).join("");
}

(async function bootstrapNotes() {
  try {
    const user = await loadCurrentUser();

    if (!user) {
      document.getElementById("notes-list").textContent = "Please log in first.";
      return;
    }

    // Owner ID is no longer needed in the UI; backend derives from session.
    await loadNotes("");
  } catch (error) {
    document.getElementById("notes-list").textContent = error.message;
  }
})();

document.getElementById("search-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);
  await loadNotes(formData.get("search"));
});

document.getElementById("create-note-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);
  const payload = {
    title: formData.get("title"),
    body: formData.get("body"),
    pinned: formData.get("pinned") === "on"
  };

  // do not send ownerId; backend uses authenticated user.
  await api("/api/notes", {
    method: "POST",
    body: JSON.stringify(payload)
  });

  await loadNotes("");
  event.currentTarget.reset();
});