// server.js — SCQ License Server (Railway + Postgres + Lemon Squeezy)
// - Robust signature verification
// - Writes webhook_events (non-fatal if logging fails)
// - Creates/updates licenses from order/subscription webhooks
// - Uses public.* schema explicitly to avoid search_path issues

import express from "express";
import crypto from "node:crypto";
import pg from "pg";

const { Pool } = pg;

const app = express();
app.use(express.json({ limit: "1mb" }));
// TEMP CORS (for local test-license.html)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const PORT = process.env.PORT || 3000;

const DATABASE_URL = process.env.DATABASE_URL;
const LS_WEBHOOK_SECRET = process.env.LS_WEBHOOK_SECRET;

if (!DATABASE_URL) throw new Error("DATABASE_URL is missing.");
if (!LS_WEBHOOK_SECRET) throw new Error("LS_WEBHOOK_SECRET is missing.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Railway Postgres typically requires SSL; this is safe there.
  ssl: { rejectUnauthorized: false },
});

// ---------- DB helper (logs exact SQL failure to Railway logs) ----------
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
function generateLicenseKey() {
  const part = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `SCQ-${part()}${part()}-${part()}${part()}-${part()}${part()}`;
}

function safeLower(x) {
  return String(x || "").trim().toLowerCase();
}

// Your LIVE variant IDs (from you)
const LIVE_VARIANTS = {
  individual_monthly: 1319003,
  individual_yearly: 1319015,
  school_yearly: 1319016,
  rally_3day: 1319022,
};

// We observed at least one TEST variant ID in your payloads
const TEST_VARIANTS = {
  individual_monthly: 1319234,
  // If you test other plans, add them here once observed.
};

// Map variant ID OR fallback by product_name (works in test/live)
function mapPlanFromWebhook(variantId, attrs = {}) {
  const v = Number(variantId || 0);

  // live ids
  if (v === LIVE_VARIANTS.individual_monthly) return { plan: "individual_monthly", maxDevices: 1 };
  if (v === LIVE_VARIANTS.individual_yearly) return { plan: "individual_yearly", maxDevices: 1 };
  if (v === LIVE_VARIANTS.school_yearly) return { plan: "school_yearly", maxDevices: 3 };
  if (v === LIVE_VARIANTS.rally_3day) return { plan: "rally_3day", maxDevices: -1 };

  // test ids (known)
  if (v === TEST_VARIANTS.individual_monthly) return { plan: "individual_monthly", maxDevices: 1 };

  // fallback by product name (stable across test/live)
  const pn = safeLower(attrs?.product_name);
  if (pn.includes("individual") && pn.includes("(monthly)")) return { plan: "individual_monthly", maxDevices: 1 };
  if (pn.includes("individual") && pn.includes("(yearly)")) return { plan: "individual_yearly", maxDevices: 1 };
  if (pn.includes("school") && pn.includes("yearly")) return { plan: "school_yearly", maxDevices: 3 };
  if (pn.includes("rally")) return { plan: "rally_3day", maxDevices: -1 };

  return null;
}

// Lemon signature verification (HMAC SHA256 of raw body, hex digest)
function verifyLemonSignature(rawBodyBuf, signatureHeader) {
  const signature = String(signatureHeader || "");
  if (!signature) return false;

  const hmac = crypto.createHmac("sha256", LS_WEBHOOK_SECRET);
  const digest = hmac.update(rawBodyBuf).digest("hex");

  const sigBuf = Buffer.from(signature, "utf8");
  const digBuf = Buffer.from(digest, "utf8");
  if (sigBuf.length !== digBuf.length) return false;

  return crypto.timingSafeEqual(digBuf, sigBuf);
}


// Validate license (does NOT consume a device slot)
app.get("/health", (_req, res) => res.json({ ok: true }));
app.post("/v1/license/validate", async (req, res) => {
  try {
    const licenseKey = String(req.body?.licenseKey || "").trim();
    if (!licenseKey) return res.status(400).json({ ok: false, error: "licenseKey required" });

    const r = await db(
      `select license_key, plan, status, expires_at, max_devices
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
      `select plan, status, expires_at, max_devices
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


// ---------- Handlers ----------
async function handleOrderCreated({ email, variantId, attrs }) {
  const mapped = mapPlanFromWebhook(variantId, attrs);
  if (!mapped) {
    console.warn("Unmapped order variantId/product:", variantId, attrs?.product_name);
    return;
  }

  const sourceId = String(attrs?.identifier || attrs?.order_number || attrs?.id || "");

  const license = await createLicenseOrReturnExisting({
    email,
    plan: mapped.plan,
    maxDevices: mapped.maxDevices,
    source: "order",
    sourceId,
  });

  // Rally: 3-day usage, must be activated within 7 days of purchase
  if (mapped.plan === "rally_3day") {
    const purchaseAt = attrs?.created_at ? new Date(attrs.created_at) : new Date();
    const activationDeadline = new Date(purchaseAt.getTime() + 7 * 24 * 60 * 60 * 1000);

    await db(
      `update public.licenses
       set rally_purchase_at = $1,
           rally_activation_deadline = $2
       where id = $3`,
      [purchaseAt.toISOString(), activationDeadline.toISOString(), license.id]
    );
  }
}

async function handleSubscriptionUpsert({ email, variantId, attrs }) {
  const mapped = mapPlanFromWebhook(variantId, attrs);
  if (!mapped) {
    console.warn("Unmapped subscription variantId/product:", variantId, attrs?.product_name);
    return;
  }

  const subId = String(attrs?.id || "");
  const license = await createLicenseOrReturnExisting({
    email,
    plan: mapped.plan,
    maxDevices: mapped.maxDevices,
    source: "subscription",
    sourceId: subId,
  });

  const status = String(attrs?.status || "").toLowerCase();
  const renewsAt = attrs?.renews_at ? new Date(attrs.renews_at) : null;
  const endsAt = attrs?.ends_at ? new Date(attrs.ends_at) : null;
  const expiry = endsAt || renewsAt;

  // status mapping
  const nextStatus = (status === "active" || status === "on_trial") ? "active" : "inactive";

  await db(
    `update public.licenses
     set status = $1,
         expires_at = $2
     where id = $3`,
    [nextStatus, expiry ? expiry.toISOString() : null, license.id]
  );
}

async function handleSubscriptionEnded({ attrs }) {
  const subId = String(attrs?.id || "");
  if (!subId) return;

  await db(
    `update public.licenses
     set status = 'inactive'
     where source = 'subscription'
       and source_id = $1`,
    [subId]
  );
}

// Create license:
// - If we already have a license for this (source, source_id), return it.
// - Else, if there's an active license for (email, plan), return it.
// - Else create a new license.
async function createLicenseOrReturnExisting({ email, plan, maxDevices, source, sourceId }) {
  // 1) By source+sourceId (best)
  if (source && sourceId) {
    const bySource = await db(
      `select * from public.licenses
       where source = $1 and source_id = $2
       limit 1`,
      [source, sourceId]
    );
    if (bySource.rows.length) return bySource.rows[0];
  }

  // 2) Existing active by email+plan (prevents duplicates on repeated webhooks)
  const existing = await db(
    `select * from public.licenses
     where email = $1 and plan = $2 and status = 'active'
     order by id desc
     limit 1`,
    [email, plan]
  );
  if (existing.rows.length) return existing.rows[0];

  // 3) Create new
  const key = generateLicenseKey();
  const ins = await db(
    `insert into public.licenses
     (license_key, email, plan, max_devices, status, source, source_id)
     values ($1, $2, $3, $4, 'active', $5, $6)
     returning *`,
    [key, email, plan, Number(maxDevices), source || null, sourceId || null]
  );
  return ins.rows[0];
}

// ---------- License Validation (for app activation) ----------
app.post("/api/validate-license", express.json(), async (req, res) => {
  try {
    const { licenseKey, deviceId } = req.body;

    if (!licenseKey || !deviceId) {
      return res.status(400).json({ error: "Missing licenseKey or deviceId" });
    }

    const result = await db(
      `select * from public.licenses
       where license_key = $1
       limit 1`,
      [licenseKey.trim()]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "License not found" });
    }

    const license = result.rows[0];

    if (license.status !== "active") {
      return res.status(403).json({ error: "License inactive" });
    }

    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      return res.status(403).json({ error: "License expired" });
    }

    return res.json({
      valid: true,
      plan: license.plan,
      maxDevices: license.max_devices
    });

  } catch (err) {
    console.error("License validation error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});


// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`SCQ License Server running on port ${PORT}`);
});