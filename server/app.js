const fs = require("fs");
const path = require("path");
const crypto = require("crypto"); //for secure session & CSRF tokens
const express = require("express");
const cookieParser = require("cookie-parser");
const { DEFAULT_DB_FILE, openDatabase } = require("../db");

function sendPublicFile(response, fileName) {
  response.sendFile(path.join(__dirname, "..", "public", fileName));
}

//session IDs now use crypto instead of Math.random for unpredictability.
function createSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

// per-session CSRF token generator for synchronizer-token pattern.
function createCsrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function createApp() {
  if (!fs.existsSync(DEFAULT_DB_FILE)) {
    throw new Error(
      `Database file not found at ${DEFAULT_DB_FILE}. Run "npm run init-db" first.`
    );
  }

  const db = openDatabase(DEFAULT_DB_FILE);
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use("/css", express.static(path.join(__dirname, "..", "public", "css")));
  app.use("/js", express.static(path.join(__dirname, "..", "public", "js")));

  // .use(async (request, response, next) => {
    const sessionId = request.cookies.sid;

    if (!sessionId) {
      request.currentUser = null;
      request.csrfToken = null;
      next();
      return;
    }

    const row = await db.get(
      `
        SELECT
          sessions.id AS session_id,
          sessions.csrf_token AS csrf_token,
          users.id AS id,
          users.username AS username,
          users.role AS role,
          users.display_name AS display_name
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.id = ?
      `,
      [sessionId] //parameterized, no string concat
    );

    request.currentUser = row
      ? {
          sessionId: row.session_id,
          id: row.id,
          username: row.username,
          role: row.role,
          displayName: row.display_name
        }
      : null;

    request.csrfToken = row ? row.csrf_token : null;
    next();
  });

  function requireAuth(request, response, next) {
    if (!request.currentUser) {
      response.status(401).json({ error: "Authentication required." });
      return;
    }
    next();
  }

  // server-side role check for admin-only routes.
  function requireAdmin(request, response, next) {
    if (!request.currentUser || request.currentUser.role !== "admin") {
      response.status(403).json({ error: "Admin access required." });
      return;
    }
    next();
  }

  // CSRF middleware – checks token from header/body against session token.
  function requireCsrf(request, response, next) {
    const token = request.get("x-csrf-token") || request.body.csrfToken;

    if (!request.currentUser || !request.csrfToken || token !== request.csrfToken) {
      response.status(403).json({ error: "Invalid CSRF token." });
      return;
    }

    next();
  }

  app.get("/", (_request, response) => sendPublicFile(response, "index.html"));
  app.get("/login", (_request, response) => sendPublicFile(response, "login.html"));
  app.get("/notes", (_request, response) => sendPublicFile(response, "notes.html"));
  app.get("/settings", (_request, response) => sendPublicFile(response, "settings.html"));
  app.get("/admin", (_request, response) => sendPublicFile(response, "admin.html"));

  // /api/me now also returns csrfToken so the client can store it.
  app.get("/api/me", (request, response) => {
    response.json({
      user: request.currentUser,
      csrfToken: request.currentUser ? request.csrfToken : null
    });
  });

  app.post("/api/login", async (request, response) => {
    const username = String(request.body.username || "");
    const password = String(request.body.password || "");

    // parameterized query instead of string interpolation (prevents SQLi).
    const user = await db.get(
      `
        SELECT id, username, role, display_name
        FROM users
        WHERE username = ? AND password = ?
      `,
      [username, password]
    );

    if (!user) {
      response.status(401).json({ error: "Invalid username or password." });
      return;
    }

    //delete any existing session ID cookie to prevent session fixation.
    const oldSessionId = request.cookies.sid;
    if (oldSessionId) {
      await db.run("DELETE FROM sessions WHERE id = ?", [oldSessionId]);
    }

    const sessionId = createSessionId();
    const csrfToken = createCsrfToken();

    // store CSRF token with session in DB.
    await db.run(
      "INSERT INTO sessions (id, user_id, created_at, csrf_token) VALUES (?, ?, ?, ?)",
      [sessionId, user.id, new Date().toISOString(), csrfToken]
    );

    //stronger cookie settings; httpOnly & sameSite mitigate theft/CSRF.
    response.cookie("sid", sessionId, {
      path: "/",
      httpOnly: true,
      sameSite: "lax",
      secure: false // keep false for local HTTP; set true in real HTTPS deployment
    });

    response.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        displayName: user.display_name
      },
      csrfToken
    });
  });

  // logout now requires CSRF and uses sessionId from currentUser.
  app.post("/api/logout", requireAuth, requireCsrf, async (request, response) => {
    await db.run("DELETE FROM sessions WHERE id = ?", [request.currentUser.sessionId]);

    response.clearCookie("sid", { path: "/" });
    response.json({ ok: true });
  });

  app.get("/api/notes", requireAuth, async (request, response) => {
    const search = String(request.query.search || "");
    const likeSearch = `%${search}%`;

    // do NOT trust ownerId from query; use authenticated user ID.
    const ownerId = request.currentUser.id;

    //  parameterized query for search terms as well.
    const notes = await db.all(
      `
        SELECT
          notes.id,
          notes.owner_id AS ownerId,
          users.username AS ownerUsername,
          notes.title,
          notes.body,
          notes.pinned,
          notes.created_at AS createdAt
        FROM notes
        JOIN users ON users.id = notes.owner_id
        WHERE notes.owner_id = ?
          AND (notes.title LIKE ? OR notes.body LIKE ?)
        ORDER BY notes.pinned DESC, notes.id DESC
      `,
      [ownerId, likeSearch, likeSearch]
    );

    response.json({ notes });
  });

  app.post("/api/notes", requireAuth, requireCsrf, async (request, response) => {
    // always take ownerId from session, not from the client.
    const ownerId = request.currentUser.id;
    const title = String(request.body.title || "");
    const body = String(request.body.body || "");
    const pinned = request.body.pinned ? 1 : 0;

    const result = await db.run(
      "INSERT INTO notes (owner_id, title, body, pinned, created_at) VALUES (?, ?, ?, ?, ?)",
      [ownerId, title, body, pinned, new Date().toISOString()]
    );

    response.status(201).json({
      ok: true,
      noteId: result.lastID
    });
  });

  app.get("/api/settings", requireAuth, async (request, response) => {
    // ignore userId query param; only return the logged-in user’s settings.
    const userId = request.currentUser.id;

    const settings = await db.get(
      `
        SELECT
          users.id AS userId,
          users.username,
          users.role,
          users.display_name AS displayName,
          settings.status_message AS statusMessage,
          settings.theme,
          settings.email_opt_in AS emailOptIn
        FROM settings
        JOIN users ON users.id = settings.user_id
        WHERE settings.user_id = ?
      `,
      [userId]
    );

    response.json({ settings });
  });

  app.post("/api/settings", requireAuth, requireCsrf, async (request, response) => {
    // ignore userId from body; use session identity.
    const userId = request.currentUser.id;
    const displayName = String(request.body.displayName || "");
    const statusMessage = String(request.body.statusMessage || "");
    const theme = String(request.body.theme || "classic");
    const emailOptIn = request.body.emailOptIn ? 1 : 0;

    await db.run("UPDATE users SET display_name = ? WHERE id = ?", [displayName, userId]);
    await db.run(
      "UPDATE settings SET status_message = ?, theme = ?, email_opt_in = ? WHERE user_id = ?",
      [statusMessage, theme, emailOptIn, userId]
    );

    response.json({ ok: true });
  });

  // now POST (not GET) for state change + CSRF.
  app.post("/api/settings/toggle-email", requireAuth, requireCsrf, async (request, response) => {
    const enabled = request.body.enabled === "1" || request.body.enabled === 1 ? 1 : 0;

    await db.run("UPDATE settings SET email_opt_in = ? WHERE user_id = ?", [
      enabled,
      request.currentUser.id
    ]);

    response.json({
      ok: true,
      userId: request.currentUser.id,
      emailOptIn: enabled
    });
  });

  //admin route now requires both auth and admin role.
  app.get("/api/admin/users", requireAuth, requireAdmin, async (_request, response) => {
    const users = await db.all(`
      SELECT
        users.id,
        users.username,
        users.role,
        users.display_name AS displayName,
        COUNT(notes.id) AS noteCount
      FROM users
      LEFT JOIN notes ON notes.owner_id = users.id
      GROUP BY users.id, users.username, users.role, users.display_name
      ORDER BY users.id
    `);

    response.json({ users });
  });

  return app;
}

module.exports = {
  createApp
};