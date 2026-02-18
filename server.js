import express from "express";
import crypto from "node:crypto";
import pg from "pg";

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 3000;

// ===============================
// ENVIRONMENT VARIABLES
// ===============================
const DATABASE_URL = process.env.DATABASE_URL;
const LS_WEBHOOK_SECRET = process.env.LS_WEBHOOK_SECRET;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is missing.");
}
if (!LS_WEBHOOK_SECRET) {
  throw new Error("LS_WEBHOOK_SECRET is missing.");
}

// ===============================
// DATABASE
// ===============================
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ===============================
// HEALTH CHECK
// ===============================
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// ===============================
// WEBHOOK ENDPOINT (RAW BODY)
// ===============================
app.post(
  "/webhooks/lemonsqueezy",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      // Verify signature
      const signature = req.get("X-Signature");
      if (!signature) return res.status(401).send("Missing signature");

      const hmac = crypto.createHmac("sha256", LS_WEBHOOK_SECRET);
      const digest = hmac.update(req.body).digest("hex");
        // timingSafeEqual throws if lengths differ
        const sigBuf = Buffer.from(String(signature), "utf8");
        const digBuf = Buffer.from(String(digest), "utf8");
        if (sigBuf.length !== digBuf.length || !crypto.timingSafeEqual(digBuf, sigBuf)) {
        return res.status(401).send("Invalid signature");
      }


      const payload = JSON.parse(req.body.toString("utf8"));
      const eventName = payload?.meta?.event_name;
      const data = payload?.data;
      const attrs = data?.attributes || {};

      // Save raw event for debugging
      try {
    await pool.query(
    `insert into webhook_events (event_name, payload_json)
     values ($1, $2)`,
    [eventName || "unknown", JSON.stringify(payload)]
  );
    } catch (e) {
      console.error("webhook_events insert failed:", e?.message);
      // DO NOT crash the webhook just because logging failed
    }


      // Extract variant ID
      const variantId =
        attrs?.first_order_item?.variant_id ||
        attrs?.variant_id ||
        0;

      const email = String(attrs?.user_email || "").toLowerCase();

      if (!email) {
        console.warn("No email found in webhook.");
        return res.status(200).json({ ok: true });
      }

      // Route event
      if (eventName === "order_created") {
        await handleOrderCreated(variantId, email, attrs);
      }

      if (
        eventName === "subscription_created" ||
        eventName === "subscription_updated"
      ) {
        await handleSubscriptionUpsert(variantId, email, attrs);
      }

      if (
        eventName === "subscription_cancelled" ||
        eventName === "subscription_expired"
      ) {
        await handleSubscriptionEnded(attrs);
      }

      return res.status(200).json({ ok: true });
    } catch (err) {
      console.error("Webhook error:", err?.stack || err);
      return res.status(500).send("Server error");
    }
  }
);

// ===============================
// VARIANT → PLAN MAPPING
// ===============================
function mapPlan(variantId, attrs = {}) {
  const v = Number(variantId);

  // Live variant IDs (your original)
  if (v === 1319003) return { plan: "individual_monthly", maxDevices: 1 };
  if (v === 1319015) return { plan: "individual_yearly",  maxDevices: 1 };
  if (v === 1319016) return { plan: "school_yearly",       maxDevices: 3 };
  if (v === 1319022) return { plan: "rally_3day",          maxDevices: -1 };

  // Test mode variant IDs (we've now observed one of them)
  if (v === 1319234) return { plan: "individual_monthly", maxDevices: 1 };

  // Fallback mapping by product name (works across test/live)
  const productName = String(attrs?.product_name || "").toLowerCase();

  if (productName.includes("individual") && productName.includes("(monthly)")) {
    return { plan: "individual_monthly", maxDevices: 1 };
  }
  if (productName.includes("individual") && productName.includes("(yearly)")) {
    return { plan: "individual_yearly", maxDevices: 1 };
  }
  if (productName.includes("school") && productName.includes("yearly")) {
    return { plan: "school_yearly", maxDevices: 3 };
  }
  if (productName.includes("rally")) {
    return { plan: "rally_3day", maxDevices: -1 };
  }

  return null;
}


// ===============================
// LICENSE KEY GENERATOR
// ===============================
function generateLicenseKey() {
  const part = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `SCQ-${part()}${part()}-${part()}${part()}-${part()}${part()}`;
}

// ===============================
// ORDER CREATED (Rally)
// ===============================
async function handleOrderCreated(variantId, email, attrs) {
  const mapped = mapPlan(variantId, attrs);
  if (!mapped) return;

  const license = await createLicenseIfNotExists(
    email,
    mapped.plan,
    mapped.maxDevices,
    "order",
    attrs?.identifier || attrs?.order_number
  );

  // Rally logic: purchase + 7 day activation window
  if (mapped.plan === "rally_3day") {
    const purchaseAt = new Date(attrs?.created_at || Date.now());
    const activationDeadline = new Date(
      purchaseAt.getTime() + 7 * 24 * 60 * 60 * 1000
    );

    await pool.query(
      `update licenses
       set rally_purchase_at=$1,
           rally_activation_deadline=$2
       where id=$3`,
      [purchaseAt.toISOString(), activationDeadline.toISOString(), license.id]
    );
  }
}

// ===============================
// SUBSCRIPTION CREATED / UPDATED
// ===============================
async function handleSubscriptionUpsert(variantId, email, attrs) {
  const mapped = mapPlan(variantId, attrs);
  if (!mapped) return;

  const license = await createLicenseIfNotExists(
    email,
    mapped.plan,
    mapped.maxDevices,
    "subscription",
    attrs?.id
  );

  const renewsAt = attrs?.renews_at ? new Date(attrs.renews_at) : null;
  const endsAt = attrs?.ends_at ? new Date(attrs.ends_at) : null;
  const status = attrs?.status;

  const expiry = endsAt || renewsAt;

  if (expiry) {
    await pool.query(
      `update licenses
       set expires_at=$1,
           status=$2
       where id=$3`,
      [
        expiry.toISOString(),
        status === "active" || status === "on_trial" ? "active" : "inactive",
        license.id
      ]
    );
  }
}

// ===============================
// SUBSCRIPTION CANCELLED / EXPIRED
// ===============================
async function handleSubscriptionEnded(attrs) {
  const subId = attrs?.id;
  if (!subId) return;

  await pool.query(
    `update licenses
     set status='inactive'
     where source='subscription'
     and source_id=$1`,
    [subId]
  );
}

// ===============================
// CREATE LICENSE (IF NOT EXISTS)
// ===============================
async function createLicenseIfNotExists(
  email,
  plan,
  maxDevices,
  source,
  sourceId
) {
  const existing = await pool.query(
    `select * from licenses
     where email=$1
     and plan=$2
     and status='active'
     limit 1`,
    [email, plan]
  );

  if (existing.rows.length) return existing.rows[0];

  const key = generateLicenseKey();

  const result = await pool.query(
    `insert into licenses
     (license_key, email, plan, max_devices, status, source, source_id)
     values ($1,$2,$3,$4,'active',$5,$6)
     returning *`,
    [key, email, plan, maxDevices, source, String(sourceId || "")]
  );

  return result.rows[0];
}

// ===============================
// START SERVER
// ===============================
app.listen(PORT, () => {
  console.log(`SCQ License Server running on port ${PORT}`);
});
