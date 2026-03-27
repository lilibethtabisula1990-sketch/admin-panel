const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const SESSION_SECRET = "admin-session-secret-change-this";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.warn("DATABASE_URL is missing. Set it to your Render Postgres connection string.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "admin.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 12,
    },
  })
);

app.use(express.static(path.join(__dirname, "public")));

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

function generateKey(len = 20) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(len);
  const out = [];
  for (let i = 0; i < len; i++) {
    out.push(alphabet[bytes[i] % alphabet.length]);
  }
  return out.join("").match(/.{1,5}/g).join("-");
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_keys (
      id SERIAL PRIMARY KEY,
      key_value TEXT UNIQUE NOT NULL,
      label TEXT,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: "db_error" });
  }
});

app.post("/api/login", (req, res) => {
  const { password } = req.body;

  if (password && password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    return res.json({ ok: true });
  }

  return res.status(401).json({ ok: false, error: "Invalid password" });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("admin.sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

app.get("/api/keys", requireAuth, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, key_value, label, expires_at, created_at,
      (expires_at IS NOT NULL AND expires_at < NOW()) AS expired
     FROM access_keys
     ORDER BY created_at DESC`
  );
  res.json({ keys: rows });
});

app.post("/api/keys", requireAuth, async (req, res) => {
  const label = (req.body.label || "").trim() || null;
  const expiresAtRaw = req.body.expiresAt || null;

  let expiresAt = null;
  if (expiresAtRaw) {
    const dt = new Date(expiresAtRaw);
    if (Number.isNaN(dt.getTime())) {
      return res.status(400).json({ error: "Invalid expiration date" });
    }
    expiresAt = dt.toISOString();
  }

  let keyValue = generateKey(20);
  for (let i = 0; i < 5; i++) {
    const exists = await pool.query(
      "SELECT 1 FROM access_keys WHERE key_value = $1",
      [keyValue]
    );
    if (exists.rowCount === 0) break;
    keyValue = generateKey(20);
  }

  const { rows } = await pool.query(
    `INSERT INTO access_keys (key_value, label, expires_at)
     VALUES ($1, $2, $3)
     RETURNING id, key_value, label, expires_at, created_at`,
    [keyValue, label, expiresAt]
  );

  res.json({ key: rows[0] });
});

app.delete("/api/keys/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "Invalid key id" });

  const result = await pool.query("DELETE FROM access_keys WHERE id = $1", [id]);
  if (result.rowCount === 0) return res.status(404).json({ error: "Key not found" });
  res.json({ ok: true });
});

app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database:", err);
    process.exit(1);
  });  const expiresAtRaw = req.body.expiresAt || null;

  let expiresAt = null;
  if (expiresAtRaw) {
    const dt = new Date(expiresAtRaw);
    if (Number.isNaN(dt.getTime())) {
      return res.status(400).json({ error: "Invalid expiration date" });
    }
    expiresAt = dt.toISOString();
  }

  let keyValue = generateKey(20);
  for (let i = 0; i < 5; i++) {
    const exists = await pool.query(
      "SELECT 1 FROM access_keys WHERE key_value = $1",
      [keyValue]
    );
    if (exists.rowCount === 0) break;
    keyValue = generateKey(20);
  }

  const { rows } = await pool.query(
    `INSERT INTO access_keys (key_value, label, expires_at)
     VALUES ($1, $2, $3)
     RETURNING id, key_value, label, expires_at, created_at`,
    [keyValue, label, expiresAt]
  );

  res.json({ key: rows[0] });
});

app.delete("/api/keys/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "Invalid key id" });

  const result = await pool.query("DELETE FROM access_keys WHERE id = $1", [id]);
  if (result.rowCount === 0) return res.status(404).json({ error: "Key not found" });
  res.json({ ok: true });
});

app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database:", err);
    process.exit(1);
  });
