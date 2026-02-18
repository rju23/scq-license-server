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

// ---------- Routes ----------
app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/webhooks/lemonsqueezy", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const signature = req.get("X-Signature");
    if (!verifyLemonSignature(req.body, signature)) {
      return res.status(401).send("Invalid signature");
    }

    const payload = JSON.parse(req.body.toString("utf8"));
    const eventName = payload?.meta?.event_name || "unknown";
    const data = payload?.data || {};
    const attrs = data?.attributes || {};

    // Best-effort logging: DO NOT fail the webhook if logging fails
    try {
      await db(
        `insert into public.webhook_events (event_name, payload_json)
         values ($1, $2::jsonb)`,
        [eventName, JSON.stringify(payload)]
      );
    } catch (e) {
      console.error("webhook_events insert failed (ignored):", e?.message || e);
    }

    // Extract common fields
    const email = safeLower(attrs?.user_email);
    const variantId =
      attrs?.first_order_item?.variant_id ??
      attrs?.variant_id ??
      attrs?.first_subscription_item?.variant_id ?? // sometimes present
      0;

    // If no email, we can’t associate a license. Still return OK to prevent retries.
    if (!email) return res.status(200).json({ ok: true });

    if (eventName === "order_created") {
      await handleOrderCreated({ email, variantId, attrs });
    } else if (eventName === "subscription_created" || eventName === "subscription_updated") {
      await handleSubscriptionUpsert({ email, variantId, attrs });
    } else if (eventName === "subscription_cancelled" || eventName === "subscription_expired") {
      await handleSubscriptionEnded({ attrs });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("Webhook error:", err?.stack || err);
    return res.status(500).send("Server error");
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