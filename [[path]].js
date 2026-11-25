const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extra }
  });
}

function cookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const part = raw.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return part ? decodeURIComponent(part.slice(name.length + 1)) : null;
}

function randomToken(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(data, b => b.toString(16).padStart(2, "0")).join("");
}

function hex(buffer) {
  return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, "0")).join("");
}

async function passwordHash(password, saltHex) {
  const salt = saltHex ? Uint8Array.from(saltHex.match(/.{2}/g).map(x => parseInt(x, 16))) : crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, material, 256);
  return { salt: hex(salt), hash: hex(bits) };
}

function validEmail(email) {
  return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

async function getUser(request, env) {
  const token = cookie(request, "mk_session");
  if (!token) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const tokenHash = hex(digest);
  const row = await env.DB.prepare(`
    SELECT u.id, u.email, s.expires_at,
      COALESCE(sub.status, 'free') AS subscription_status,
      COALESCE(sub.plan_code, 'free') AS plan_code,
      sub.current_period_end
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    LEFT JOIN subscriptions sub ON sub.user_id = u.id
      AND sub.status = 'active'
    WHERE s.token_hash = ? AND s.expires_at > ?
    LIMIT 1
  `).bind(tokenHash, Date.now()).first();
  return row || null;
}

async function createSession(userId, env) {
  const token = randomToken(32);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const expires = Date.now() + 1000 * 60 * 60 * 24 * 14;
  await env.DB.prepare("INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(crypto.randomUUID(), userId, hex(digest), expires, Date.now()).run();
  return { token, expires };
}

function sessionCookie(token, maxAge = 1209600) {
  return `mk_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function usageSummary(user, env) {
  const today = new Date().toISOString().slice(0, 10);
  const month = today.slice(0, 7);
  const row = await env.DB.prepare(`
    SELECT
      SUM(CASE WHEN period_key = ? THEN operations ELSE 0 END) AS today_operations,
      SUM(CASE WHEN substr(period_key, 1, 7) = ? THEN operations ELSE 0 END) AS month_operations
    FROM usage_counters WHERE user_id = ?
  `).bind(today, month, user.id).first();
  const isPro = user.plan_code === "pro" && user.subscription_status === "active";
  return {
    plan: isPro ? "pro" : "free",
    today_operations: row?.today_operations || 0,
    month_operations: row?.month_operations || 0,
    limits: isPro
      ? { daily_operations: 100, monthly_operations: 500, batch_processing: true }
      : { daily_operations: 10, monthly_operations: 100, batch_processing: false }
  };
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");
  const method = request.method.toUpperCase();

  if (!env.DB) return json({ error: "D1 database binding DB is not configured." }, 503);

  if (method !== "GET" && !sameOrigin(request)) {
    return json({ error: "Cross-origin request rejected." }, 403);
  }

  if (path === "health" && method === "GET") {
    return json({ ok: true, service: "MediaKitly API", payments: "not_configured", ads: "not_configured" });
  }

  if (path === "plans" && method === "GET") {
    return json({
      plans: [
        { code: "free", name: "Free", price_pkr: 0, daily_operations: 10, monthly_operations: 100, ads: "Adsterra placements may be shown" },
        { code: "pro", name: "Pro", price_pkr: 499, interval: "month", daily_operations: 100, monthly_operations: 500, ads: "One limited placement may be shown" }
      ],
      note: "Launch limits and price are provisional. Configure billing only after merchant approval."
    });
  }

  if (path === "auth/register" && method === "POST") {
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON." }, 400); }
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!validEmail(email)) return json({ error: "Enter a valid email address." }, 400);
    if (password.length < 12 || password.length > 128) return json({ error: "Password must be 12–128 characters." }, 400);
    const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
    if (existing) return json({ error: "An account with this email already exists." }, 409);
    const pw = await passwordHash(password);
    const userId = crypto.randomUUID();
    const now = Date.now();
    await env.DB.prepare("INSERT INTO users (id, email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(userId, email, pw.hash, pw.salt, now).run();
    const session = await createSession(userId, env);
    return json({ ok: true, user: { id: userId, email, plan: "free" }, note: "Email verification is not implemented yet." }, 201, {
      "set-cookie": sessionCookie(session.token)
    });
  }

  if (path === "auth/login" && method === "POST") {
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON." }, 400); }
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const user = await env.DB.prepare("SELECT id, email, password_hash, password_salt FROM users WHERE email = ?").bind(email).first();
    if (!user) return json({ error: "Invalid email or password." }, 401);
    const check = await passwordHash(password, user.password_salt);
    if (check.hash !== user.password_hash) return json({ error: "Invalid email or password." }, 401);
    const session = await createSession(user.id, env);
    return json({ ok: true, user: { id: user.id, email: user.email } }, 200, {
      "set-cookie": sessionCookie(session.token)
    });
  }

  if (path === "auth/logout" && method === "POST") {
    const token = cookie(request, "mk_session");
    if (token) {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(hex(digest)).run();
    }
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }

  const user = await getUser(request, env);
  if (path === "me" && method === "GET") {
    if (!user) return json({ authenticated: false, plan: "free" });
    return json({ authenticated: true, user: { id: user.id, email: user.email }, subscription: {
      plan: user.plan_code, status: user.subscription_status, current_period_end: user.current_period_end || null
    }});
  }

  if (path === "usage" && method === "GET") {
    if (!user) return json({ error: "Sign in to view account usage." }, 401);
    return json(await usageSummary(user, env));
  }

  if (path === "usage/consume" && method === "POST") {
    if (!user) return json({ error: "Sign in before recording usage." }, 401);
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON." }, 400); }
    const tool = String(body.tool || "").slice(0, 40);
    if (!/^[a-z0-9_-]{2,40}$/i.test(tool)) return json({ error: "Invalid tool identifier." }, 400);
    const summary = await usageSummary(user, env);
    if (summary.today_operations >= summary.limits.daily_operations || summary.month_operations >= summary.limits.monthly_operations) {
      return json({ allowed: false, error: "Usage limit reached.", usage: summary }, 429);
    }
    const day = new Date().toISOString().slice(0, 10);
    await env.DB.prepare(`
      INSERT INTO usage_counters (user_id, period_key, operations)
      VALUES (?, ?, 1)
      ON CONFLICT(user_id, period_key) DO UPDATE SET operations = operations + 1
    `).bind(user.id, day).run();
    return json({ allowed: true, usage: await usageSummary(user, env) });
  }

  if (path === "billing/checkout" && method === "POST") {
    if (!user) return json({ error: "Sign in before upgrading." }, 401);
    return json({
      error: "Safepay is not configured. Merchant approval, server key, plan ID and webhook secret are required.",
      next_step: "Complete Safepay merchant onboarding and configure secrets before enabling checkout."
    }, 503);
  }

  if (path === "webhooks/safepay" && method === "POST") {
    return json({
      error: "Webhook handler is intentionally disabled until Safepay's exact webhook version, signing format and merchant secrets are configured."
    }, 503);
  }

  return json({ error: "API route not found." }, 404);
}
