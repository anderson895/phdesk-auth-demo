// PHdesk auth demo: create account, login, logout
// Cloudflare Workers + D1 (SQLite). Run locally: npm run db:init, then npm run dev

const PBKDF2_ITERATIONS = 100000; // the most Cloudflare Workers allows for PBKDF2
const SESSION_DAYS = 7;

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const method = request.method;

    if (pathname === "/" && method === "GET") return home(request, env);
    if (pathname === "/signup" && method === "GET") return page("Create account", signupForm());
    if (pathname === "/signup" && method === "POST") return signup(request, env);
    if (pathname === "/login" && method === "GET") return page("Login", loginForm());
    if (pathname === "/login" && method === "POST") return login(request, env);
    if (pathname === "/logout" && method === "POST") return logout(request, env);
    return new Response("Not found", { status: 404 });
  },
};

// ---------- 1. CREATE ACCOUNT ----------
async function signup(request, env) {
  const form = await request.formData();
  const email = String(form.get("email") || "").trim().toLowerCase();
  const password = String(form.get("password") || "");

  if (!email.includes("@") || password.length < 8) {
    const error = "Gumamit ng valid na email at password na 8+ characters.";
    return page("Create account", signupForm(error), 400);
  }

  const existing = await env.DB
    .prepare("SELECT id FROM users WHERE email = ?")
    .bind(email)
    .first();
  if (existing) {
    const error = "May account na ang email na ito.";
    return page("Create account", signupForm(error), 409);
  }

  const passwordHash = await hashPassword(password); // the real password is never saved
  const result = await env.DB.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)")
    .bind(email, passwordHash)
    .run();

  return startSession(env, result.meta.last_row_id);
}

// ---------- 2. LOGIN ----------
async function login(request, env) {
  const form = await request.formData();
  const email = String(form.get("email") || "").trim().toLowerCase();
  const password = String(form.get("password") || "");

  const user = await env.DB.prepare("SELECT id, password_hash FROM users WHERE email = ?").bind(email).first();
  const ok = user && (await verifyPassword(password, user.password_hash));
  if (!ok) {
    return page("Login", loginForm("Mali ang email o password."), 401); // same message for both cases
  }

  return startSession(env, user.id);
}

// ---------- 3. LOGOUT ----------
async function logout(request, env) {
  const token = getCookie(request, "session");
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(await sha256(token)).run();
  }
  return redirect("/login", "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
}

// ---------- HOME: for logged-in users only ----------
async function home(request, env) {
  const user = await currentUser(request, env);
  if (!user) return redirect("/login");

  return page("Home", `
    <h1>Hi, ${escapeHtml(user.email)}! 👋</h1>
    <p class="ok">Naka-login ka.</p>
    <form method="POST" action="/logout"><button>Logout</button></form>`);
}

// ---------- PASSWORDS: salt + hash (PBKDF2-SHA256) ----------
async function hashPassword(password) {
  // a new random salt for every account
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toHex(salt)}$${toHex(hash)}`;
}

async function verifyPassword(password, stored) {
  const [, iterations, saltHex, hashHex] = stored.split("$");
  // hash the typed password the same way, then compare the two hashes
  const hash = await pbkdf2(password, fromHex(saltHex), Number(iterations));
  return crypto.subtle.timingSafeEqual(hash, fromHex(hashHex));
}

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256
  );
  return new Uint8Array(bits);
}

// ---------- SESSIONS: a random token in a cookie ----------
async function startSession(env, userId) {
  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;

  await env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
    .bind(await sha256(token), userId, expiresAt) // the database only keeps the token's hash
    .run();

  return redirect("/", `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}`);
}

async function currentUser(request, env) {
  const token = getCookie(request, "session");
  if (!token) return null;

  return env.DB.prepare(
    `SELECT users.id, users.email FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.id = ? AND sessions.expires_at > ?`
  ).bind(await sha256(token), Math.floor(Date.now() / 1000)).first();
}

// ---------- small helpers ----------
async function sha256(text) {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const found = cookies.split(";").map((c) => c.trim()).find((c) => c.startsWith(name + "="));
  return found ? found.slice(name.length + 1) : null;
}

function redirect(location, cookie) {
  const headers = new Headers({ Location: location });
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(null, { status: 303, headers });
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  return new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
}

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// ---------- the HTML pages ----------
function signupForm(error = "") {
  return `
    <h1>Create account</h1>
    ${error ? `<p class="err">${error}</p>` : ""}
    <form method="POST" action="/signup">
      <label>Email
        <input name="email" type="email" required>
      </label>
      <label>Password
        <input name="password" type="password"
               required minlength="8">
      </label>
      <button>Create account</button>
    </form>
    <p class="alt">
      May account na? <a href="/login">Login</a>
    </p>`;
}

function loginForm(error = "") {
  return `
    <h1>Login</h1>
    ${error ? `<p class="err">${error}</p>` : ""}
    <form method="POST" action="/login">
      <label>Email <input name="email" type="email" required autocomplete="email"></label>
      <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
      <button>Login</button>
    </form>
    <p class="alt">Wala pang account? <a href="/signup">Create account</a></p>`;
}

function page(title, body, status = 200) {
  return new Response(
    `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · PHdesk Auth Demo</title>
<style>
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #F2F5FA; font-family: system-ui, sans-serif; color: #111827; }
  main { width: 360px; padding: 32px; border-radius: 20px; background: #fff; box-shadow: 0 20px 40px -20px rgba(1,16,59,.35); }
  .brand { margin: 0 0 18px; font-weight: 800; color: #01103B; letter-spacing: .02em; }
  h1 { margin: 0 0 18px; font-size: 26px; }
  label { display: block; margin-bottom: 14px; font-size: 14px; font-weight: 600; color: #4B5563; }
  input { display: block; width: 100%; box-sizing: border-box; margin-top: 6px; padding: 12px; border: 1.5px solid #D1D5DB; border-radius: 10px; font-size: 16px; }
  button { width: 100%; padding: 12px; border: 0; border-radius: 10px; background: #0A6CFF; color: #fff; font-size: 16px; font-weight: 700; cursor: pointer; }
  .err { padding: 10px 12px; border-radius: 10px; background: #FEECEC; color: #B42318; font-size: 14px; }
  .ok { color: #1E8A3C; font-weight: 600; }
  .alt { margin: 16px 0 0; font-size: 14px; text-align: center; }
</style>
</head>
<body><main><p class="brand">PHdesk Auth Demo</p>${body}</main></body>
</html>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8" } }
  );
}
