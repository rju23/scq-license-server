// server.js — SCQ License Server (Railway + Postgres + Lemon Squeezy + Resend)
// - Verifies Lemon Squeezy HMAC signature
// - Logs webhook_events (non-fatal if it fails)
// - Creates licenses for order_created + subscription_created/updated
// - Tracks activations (device limits)
// - Emails license key to customer using Resend (verified domain required)

import express from "express";
import crypto from "node:crypto";
import pg from "pg";
import { Resend } from "resend";

const { Pool } = pg;

const APP_NAME = process.env.APP_NAME || "SCQ Scoreboard";

// REQUIRED
const DATABASE_URL = process.env.DATABASE_URL;
const LS_WEBHOOK_SECRET = process.env.LS_WEBHOOK_SECRET;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const MAIL_FROM = process.env.MAIL_FROM; // e.g. SCQ Scoreboard <support@scqscoreboard.com>

// OPTIONAL
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || ""; // used in email body only
const PORT = Number(process.env.PORT || 8080);

if (!DATABASE_URL) throw new Error("DATABASE_URL is missing.");
if (!LS_WEBHOOK_SECRET) throw new Error("LS_WEBHOOK_SECRET is missing.");
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

function planLabel(plan) {
  switch (plan) {
    case "individual_monthly":
      return "Individual (Monthly)";
    case "individual_yearly":
      return "Individual (Yearly)";
    case "school_yearly":
      return "School (Yearly)";
    case "rally_3day":
      return "Rally (3-day)";
    default:
      return plan || "Unknown";
  }
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

// ---------- Variant mapping ----------
const LIVE_VARIANTS = {
  individual_monthly: 1319003,
  individual_yearly: 1319015,
  school_yearly: 1319016,
  rally_3day: 1319022,
};

// Add test ids as you observe them
const TEST_VARIANTS = {
  individual_monthly: 1319234,
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

// ---------- Email ----------
async function sendLicenseEmail({ to, licenseKey, plan, maxDevices }) {
  const subject = `${APP_NAME} — Your License Key`;

  const text =
`${APP_NAME}

Thanks for your purchase.

License key:
${licenseKey}

Plan: ${planLabel(plan)}
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

// ---------- License creation ----------
async function createLicenseOrReturnExisting({ email, plan, maxDevices, source, sourceId }) {
  // 1) By source+sourceId (best)
  if (source && sourceId) {
    const bySource = await db(
      `select * from public.licenses
       where source = $1 and source_id = $2
       limit 1`,
      [source, sourceId]
    );
    if (bySource.rows.length) return { license: bySource.rows[0], created: false };
  }

  // 2) Existing active by email+plan
  const existing = await db(
    `select * from public.licenses
     where email = $1 and plan = $2 and status = 'active'
     order by id desc
     limit 1`,
    [email, plan]
  );
  if (existing.rows.length) return { license: existing.rows[0], created: false };

  // 3) Create new
  const key = generateLicenseKey();
  const ins = await db(
    `insert into public.licenses
     (license_key, email, plan, max_devices, status, source, source_id)
     values ($1, $2, $3, $4, 'active', $5, $6)
     returning *`,
    [key, email, plan, Number(maxDevices), source || null, sourceId || null]
  );

  return { license: ins.rows[0], created: true };
}

// ---------- Handlers ----------
async function handleOrderCreated({ email, variantId, attrs }) {
  const mapped = mapPlanFromWebhook(variantId, attrs);
  if (!mapped) {
    console.warn("Unmapped order variantId/product:", variantId, attrs?.product_name);
    return;
  }

  const sourceId = String(attrs?.identifier || attrs?.order_number || attrs?.id || "");

  const { license, created } = await createLicenseOrReturnExisting({
    email,
    plan: mapped.plan,
    maxDevices: mapped.maxDevices,
    source: "order",
    sourceId,
  });

  if (created) {
    try {
      await sendLicenseEmail({
        to: email,
        licenseKey: license.license_key,
        plan: license.plan,
        maxDevices: license.max_devices,
      });
    } catch (e) {
      console.error("Failed to send license email (order):", e?.message || e);
    }
  }

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

  const { license, created } = await createLicenseOrReturnExisting({
    email,
    plan: mapped.plan,
    maxDevices: mapped.maxDevices,
    source: "subscription",
    sourceId: subId,
  });

  if (created) {
    try {
      await sendLicenseEmail({
        to: email,
        licenseKey: license.license_key,
        plan: license.plan,
        maxDevices: license.max_devices,
      });
    } catch (e) {
      console.error("Failed to send license email (subscription):", e?.message || e);
    }
  }

  // Update status/expiry from subscription
  const status = String(attrs?.status || "").toLowerCase();
  const renewsAt = attrs?.renews_at ? new Date(attrs.renews_at) : null;
  const endsAt = attrs?.ends_at ? new Date(attrs.ends_at) : null;
  const expiry = endsAt || renewsAt;

  const nextStatus = status === "active" || status === "on_trial" ? "active" : "inactive";

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

// ---------- Express app ----------
const app = express();

// Lemon webhook needs RAW body for signature check
app.post(
  "/webhooks/lemonsqueezy",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const rawBody = req.body;
      const signature = req.headers["x-signature"];

      if (!verifyLemonSignature(rawBody, signature)) {
        console.error("Invalid Lemon signature");
        return res.status(401).send("Invalid signature");
      }

      const payload = JSON.parse(rawBody.toString("utf8"));
      const eventName = payload?.meta?.event_name;

      const data = payload?.data;
      const attrs = data?.attributes || {};

      const email = String(attrs?.user_email || "").trim();
      const variantId = attrs?.first_order_item?.variant_id || attrs?.variant_id;

      // log webhook (non-fatal)
      try {
        await db(
          `insert into public.webhook_events (event_name, payload_json)
           values ($1, $2::jsonb)`,
          [eventName, JSON.stringify(payload)]
        );
      } catch (e) {
        console.error("webhook_events insert failed (ignored):", e?.message);
      }

      if (!data || !eventName) {
        return res.status(200).send("No-op");
      }

      switch (eventName) {
        case "order_created":
          await handleOrderCreated({ email, variantId, attrs });
          break;

        case "subscription_created":
        case "subscription_updated":
          await handleSubscriptionUpsert({ email, variantId, attrs });
          break;

        case "subscription_cancelled":
        case "subscription_expired":
          await handleSubscriptionEnded({ attrs });
          break;

        default:
          console.log("Unhandled event:", eventName);
      }

      return res.status(200).send("OK");
    } catch (err) {
      console.error("Webhook error:", err?.stack || err);
      return res.status(500).send("Server error");
    }
  }
);

// JSON endpoints (after webhook raw route)
app.use(express.json({ limit: "1mb" }));

// TEMP CORS (for local test-license.html)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

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

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`SCQ License Server running on port ${PORT}`);
});
