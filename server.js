// server.js — SCQ License Server (Railway + Postgres + Resend)
// - Manual license creation via admin endpoints
// - Tracks activations (device limits)
// - Feature pack granting per license
// - Emails license key to customer using Resend

import express from "express";
import crypto from "node:crypto";
import pg from "pg";
import { Resend } from "resend";

const { Pool } = pg;

const APP_NAME = process.env.APP_NAME || "SCQ Scoreboard";

// REQUIRED
const DATABASE_URL = process.env.DATABASE_URL;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const MAIL_FROM = process.env.MAIL_FROM; // e.g. SCQ Scoreboard <support@scqscoreboard.com>

// OPTIONAL
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || ""; // used in email body only
const PORT = Number(process.env.PORT || 8080);

if (!DATABASE_URL) throw new Error("DATABASE_URL is missing.");
if (!RESEND_API_KEY) throw new Error("RESEND_API_KEY is missing.");
if (!MAIL_FROM) throw new Error("MAIL_FROM is missing (must be verified domain).");

console.log("RESEND KEY PRESENT:", !!RESEND_API_KEY);
console.log("MAIL_FROM:", MAIL_FROM);

const resend = new Resend(RESEND_API_KEY);

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Railway Postgres typically requires SSL
  ssl: { rejectUnauthorized: false },
});

// ---------- DB helper ----------
async function db(query, params) {
  try {
    return await pool.query(query, params);
  } catch (e) {
    console.error("DB ERROR:", e?.message || e);
    console.error("DB QUERY:", query);
    console.error("DB PARAMS:", params);
    throw e;
  }
}

// ---------- Utils ----------
function safeLower(x) {
  return String(x || "").trim().toLowerCase();
}

function generateLicenseKey() {
  const part = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `SCQ-${part()}${part()}-${part()}${part()}-${part()}${part()}`;
}

// ---------- Email ----------
async function sendLicenseEmail({ to, licenseKey, plan, maxDevices }) {
  const subject = `${APP_NAME} — Your License Key`;

  const text =
`${APP_NAME}

Thanks for your purchase.

License key:
${licenseKey}

Plan: Core License
Devices allowed: ${maxDevices === -1 ? "Unlimited" : maxDevices}

How to activate:
1) Open the app
2) Enter the license key when prompted
3) Click Activate on this device

Need help? ${SUPPORT_EMAIL || "Reply to this email."}
`;

  console.log("EMAIL: about to send", { to, from: MAIL_FROM });

  const resp = await resend.emails.send({
    from: MAIL_FROM,
    to,
    subject,
    text,
  });

  console.log("EMAIL: resend response", resp);

  if (resp?.error) {
    // Make sure you *see* the real failure in Railway logs
    throw new Error(resp.error.message || "Resend failed");
  }

  console.log("EMAIL_SENT:", { to, id: resp?.data?.id });
}

// ---------- Express app ----------
const app = express();

app.use(express.json({ limit: "1mb" }));

// CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-admin-secret");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.get("/health", (_req, res) => res.json({ ok: true }));

// =========================================================
// Feedback endpoint (Website -> License Server)
// POST /v1/feedback
// =========================================================

const FEEDBACK_TO_EMAIL = process.env.FEEDBACK_TO_EMAIL || SUPPORT_EMAIL || "";
const FEEDBACK_MIN_SECONDS = Number(process.env.FEEDBACK_MIN_SECONDS || 15);
const FEEDBACK_ALLOW_ORIGIN = process.env.FEEDBACK_ALLOW_ORIGIN || "*";

// lightweight in-memory rate limit (per IP) to reduce spam
const feedbackLastByIp = new Map(); // ip -> ms

function cleanStr(x, max = 2000) {
  return String(x || "").replace(/\s+/g, " ").trim().slice(0, max);
}

function isEmailLike(x) {
  const s = String(x || "").trim();
  if (!s) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

app.post("/v1/feedback", async (req, res) => {
  try {
    // CORS (optional tightening)
    res.setHeader("Access-Control-Allow-Origin", FEEDBACK_ALLOW_ORIGIN);
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") return res.sendStatus(204);

    // rate limit
    const ip =
      (req.headers["cf-connecting-ip"] ||
        req.headers["x-forwarded-for"] ||
        req.socket.remoteAddress ||
        "") + "";
    const now = Date.now();
    const last = feedbackLastByIp.get(ip) || 0;
    if (now - last < FEEDBACK_MIN_SECONDS * 1000) {
      return res.status(429).json({ ok: false, error: "rate_limited" });
    }
    feedbackLastByIp.set(ip, now);

    const name = cleanStr(req.body?.name, 120);
    const emailRaw = cleanStr(req.body?.email, 160);
    const email = isEmailLike(emailRaw) ? emailRaw : "";
    const category = cleanStr(req.body?.category, 40) || "General";
    const message = cleanStr(req.body?.message, 4000);
    const appVersion = cleanStr(req.body?.appVersion, 80);
    const pageUrl = cleanStr(req.body?.pageUrl, 300);
    const userAgent = cleanStr(req.headers["user-agent"], 300);

    if (!message || message.length < 5) {
      return res.status(400).json({ ok: false, error: "message_required" });
    }

    // 1) Store in Postgres (recommended)
    try {
      await db(
        `insert into public.feedback
         (name, email, category, message, app_version, page_url, user_agent, ip)
         values ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [name || null, email || null, category, message, appVersion || null, pageUrl || null, userAgent || null, ip || null]
      );
    } catch (e) {
      console.error("feedback insert failed (ignored):", e?.message || e);
      // still continue to email
    }

    // 2) Email you the feedback (Resend)
    if (!FEEDBACK_TO_EMAIL) {
      return res.json({ ok: true, stored: true, emailed: false, note: "FEEDBACK_TO_EMAIL not set" });
    }

    const subject = `${APP_NAME} Feedback — ${category}`;
    const text =
`New feedback received

Category: ${category}
From: ${name || "(no name)"}${email ? ` <${email}>` : ""}
App version: ${appVersion || "(not provided)"}
Page: ${pageUrl || "(not provided)"}
IP: ${ip || "(unknown)"}

Message:
${message}
`;

    const resp = await resend.emails.send({
      from: MAIL_FROM,
      to: FEEDBACK_TO_EMAIL,
      subject,
      text
    });

    if (resp?.error) {
      console.error("feedback email failed:", resp.error);
      return res.json({ ok: true, stored: true, emailed: false });
    }

    return res.json({ ok: true, stored: true, emailed: true, id: resp?.data?.id || null });
  } catch (e) {
    console.error("feedback route error:", e?.stack || e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Validate license (does NOT consume a device slot)
app.post("/v1/license/validate", async (req, res) => {
  try {
    const licenseKey = String(req.body?.licenseKey || "").trim();
    if (!licenseKey) return res.status(400).json({ ok: false, error: "licenseKey required" });

    const r = await db(
      `select license_key, plan, status, starts_at, expires_at, max_devices
       from public.licenses
       where license_key = $1
       limit 1`,
      [licenseKey]
    );

    if (!r.rows.length) return res.status(404).json({ ok: false, error: "License not found" });

    const lic = r.rows[0];
    if (String(lic.status).toLowerCase() !== "active") {
      return res.status(403).json({ ok: false, error: "License inactive" });
    }

    if (lic.starts_at && new Date(lic.starts_at).getTime() > Date.now()) {
  return res.status(403).json({
    ok: false,
    error: "Season has not started yet",
    startsAt: lic.starts_at
  });
    }
    if (lic.expires_at && new Date(lic.expires_at).getTime() <= Date.now()) {
      return res.status(403).json({ ok: false, error: "License expired", expiresAt: lic.expires_at });
    }

    const usedR = await db(
      `select count(*)::int as c
       from public.activations
       where license_key = $1`,
      [licenseKey]
    );

    const used = usedR.rows[0]?.c ?? 0;
    const max = Number(lic.max_devices ?? 1);

    return res.json({
      ok: true,
      plan: lic.plan,
      status: lic.status,
      expiresAt: lic.expires_at,
      maxDevices: max,
      usedDevices: used,
      remainingDevices: max === -1 ? 999999 : Math.max(0, max - used),
      serverTime: new Date().toISOString(),
    });
  } catch (e) {
    console.error("validate error:", e?.stack || e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Activate device (creates/updates a row in public.activations)
app.post("/v1/license/activate", async (req, res) => {
  try {
    const licenseKey = String(req.body?.licenseKey || "").trim();
    const deviceId = String(req.body?.deviceId || "").trim();
    const deviceLabel = String(req.body?.deviceLabel || "").trim() || null;

    if (!licenseKey) return res.status(400).json({ ok: false, error: "licenseKey required" });
    if (!deviceId) return res.status(400).json({ ok: false, error: "deviceId required" });

    const lr = await db(
      `select plan, status, starts_at, expires_at, max_devices, features
       from public.licenses
       where license_key = $1
       limit 1`,
      [licenseKey]
    );

    if (!lr.rows.length) return res.status(404).json({ ok: false, error: "License not found" });
    const lic = lr.rows[0];

    if (String(lic.status).toLowerCase() !== "active") {
      return res.status(403).json({ ok: false, error: "License inactive" });
    }
    if (lic.starts_at && new Date(lic.starts_at).getTime() > Date.now()) {
  return res.status(403).json({
    ok: false,
    error: "Season has not started yet",
    startsAt: lic.starts_at
  });
    }
    if (lic.expires_at && new Date(lic.expires_at).getTime() <= Date.now()) {
      return res.status(403).json({ ok: false, error: "License expired", expiresAt: lic.expires_at });
    }

    const max = Number(lic.max_devices ?? 1);

    // already activated?
    const ex = await db(
      `select id
       from public.activations
       where license_key=$1 and device_id=$2
       limit 1`,
      [licenseKey, deviceId]
    );

    if (!ex.rows.length) {
      const usedR = await db(
        `select count(*)::int as c
         from public.activations
         where license_key=$1`,
        [licenseKey]
      );
      const used = usedR.rows[0]?.c ?? 0;

      if (max !== -1 && used >= max) {
        return res.status(403).json({ ok: false, error: "Device limit reached", maxDevices: max, usedDevices: used });
      }

      await db(
        `insert into public.activations (license_key, device_id, device_label, last_seen_at)
         values ($1,$2,$3,now())`,
        [licenseKey, deviceId, deviceLabel]
      );
    } else {
      await db(
        `update public.activations
         set last_seen_at=now(), device_label=coalesce($3, device_label)
         where license_key=$1 and device_id=$2`,
        [licenseKey, deviceId, deviceLabel]
      );
    }

    const used2R = await db(
      `select count(*)::int as c
       from public.activations
       where license_key=$1`,
      [licenseKey]
    );
    const used2 = used2R.rows[0]?.c ?? 0;

    return res.json({
      ok: true,
      plan: lic.plan,
      features: lic.features || [],
      maxDevices: max,
      usedDevices: used2,
      remainingDevices: max === -1 ? 999999 : Math.max(0, max - used2),
      serverTime: new Date().toISOString(),
    });
  } catch (e) {
    console.error("activate error:", e?.stack || e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// =========================================================
// Verify device against license (periodic check from app)
// POST /v1/license/verify-device
// Body: { licenseKey, deviceId }
// =========================================================
app.post("/v1/license/verify-device", async (req, res) => {
  try {
    const licenseKey = String(req.body?.licenseKey || "").trim();
    const deviceId = String(req.body?.deviceId || "").trim();

    if (!licenseKey || !deviceId) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    // Check license exists and is active
    const lr = await db(
      `SELECT plan, status, starts_at, expires_at, max_devices, features
       FROM public.licenses
       WHERE license_key = $1
       LIMIT 1`,
      [licenseKey]
    );

    if (!lr.rows.length) {
      return res.status(404).json({ ok: false, active: false, error: "license_not_found" });
    }

    const lic = lr.rows[0];

    if (String(lic.status).toLowerCase() !== "active") {
      return res.status(200).json({ ok: true, active: false, reason: "license_inactive" });
    }

    if (lic.expires_at && new Date(lic.expires_at).getTime() <= Date.now()) {
      return res.status(200).json({ ok: true, active: false, reason: "license_expired" });
    }

    // Check device is registered
    const dr = await db(
      `SELECT id FROM public.activations
       WHERE license_key = $1 AND device_id = $2
       LIMIT 1`,
      [licenseKey, deviceId]
    );

    if (!dr.rows.length) {
      return res.status(200).json({ ok: true, active: false, reason: "device_not_registered" });
    }

    // Update last seen
    await db(
      `UPDATE public.activations
       SET last_seen_at = now()
       WHERE license_key = $1 AND device_id = $2`,
      [licenseKey, deviceId]
    );

    return res.json({
      ok: true,
      active: true,
      plan: lic.plan,
      features: lic.features || [],
    });

  } catch (e) {
    console.error("verify-device error:", e?.stack || e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// =========================================================
// Deactivate device (frees up a device slot)
// POST /v1/license/deactivate
// Body: { licenseKey, deviceId }
// =========================================================
app.post("/v1/license/deactivate", async (req, res) => {
  try {
    const licenseKey = String(req.body?.licenseKey || "").trim();
    const deviceId = String(req.body?.deviceId || "").trim();

    if (!licenseKey || !deviceId) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    // Remove the device activation record
    await db(
      `DELETE FROM public.activations
       WHERE license_key = $1 AND device_id = $2`,
      [licenseKey, deviceId]
    );

    return res.json({ ok: true, message: "Device deactivated successfully" });

  } catch (e) {
    console.error("deactivate error:", e?.stack || e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/v1/admin/grant-license", async (req, res) => {
  try {
    const { email } = req.body;

    // 🔐 SECURITY CHECK
    const secret = req.headers["x-admin-secret"];

    if (!secret || secret !== process.env.ADMIN_SECRET) {
      console.warn("UNAUTHORIZED ADMIN ATTEMPT", {
        ip: req.ip,
        time: new Date().toISOString()
      });

  return res.status(403).json({ error: "Forbidden" });
}

    const licenseKey = generateLicenseKey();

    const existing = await db(
  `select * from public.licenses
   where email = $1 and status = 'active' and plan = 'core'
   limit 1`,
  [email]
);

if (existing.rows.length) {
  return res.json({
    success: true,
    message: "User already has active premium",
    licenseKey: existing.rows[0].license_key
  });
}

    await pool.query(
  `INSERT INTO licenses (
    license_key,
    email,
    plan,
    max_devices,
    status,
    expires_at,
    source,
    features
  ) VALUES ($1, $2, 'core', 2, 'active', $3, 'manual', '[]'::jsonb)`,
  [licenseKey, email, null]
);

    res.json({
  success: true,
  licenseKey
});

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server error" });
  }
});

// =========================================================
// Grant a feature pack to an existing license
// POST /v1/admin/grant-feature
// Headers: x-admin-secret
// Body: { email, feature }
// =========================================================
app.post("/v1/admin/grant-feature", async (req, res) => {
  try {
    const secret = req.headers["x-admin-secret"];
    if (!secret || secret !== process.env.ADMIN_SECRET) {
      console.warn("UNAUTHORIZED ADMIN ATTEMPT", {
        ip: req.ip,
        time: new Date().toISOString()
      });
      return res.status(403).json({ error: "Forbidden" });
    }

    const { email, feature } = req.body;

    if (!email || !feature) {
      return res.status(400).json({ error: "email and feature are required" });
    }

    // Find their active core license
    const lr = await db(
      `SELECT id, features FROM public.licenses
       WHERE email = $1 AND status = 'active' AND plan = 'core'
       LIMIT 1`,
      [safeLower(email)]
    );

    if (!lr.rows.length) {
      return res.status(404).json({ error: "No active core license found for this email" });
    }

    const lic = lr.rows[0];
    const currentFeatures = lic.features || [];

    // Don't add duplicates
    if (currentFeatures.includes(feature)) {
      return res.json({
        ok: true,
        message: "Feature already granted",
        features: currentFeatures
      });
    }

    const updatedFeatures = [...currentFeatures, feature];

    await db(
      `UPDATE public.licenses
       SET features = $1::jsonb
       WHERE id = $2`,
      [JSON.stringify(updatedFeatures), lic.id]
    );

    return res.json({
      ok: true,
      message: "Feature granted successfully",
      email,
      feature,
      features: updatedFeatures
    });

  } catch (err) {
    console.error("grant-feature error:", err?.stack || err);
    return res.status(500).json({ error: "server_error" });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`SCQ License Server running on port ${PORT}`);
});
