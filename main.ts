const kv = await Deno.openKv();

const ADMIN_PASSWORD = Deno.env.get("ADMIN_PASSWORD");
if (!ADMIN_PASSWORD) {
  console.error("ADMIN_PASSWORD environment variable is required!");
  Deno.exit(1);
}

async function hashPassword(password: string): Promise<string> {
  const data = new TextEncoder().encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") || "*";

const corsHeaders: Record<string, string> = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const headers: Record<string, string> = {
  "content-type": "application/json; charset=utf-8",
  ...corsHeaders,
};

function json(data: object, status = 200) {
  return new Response(JSON.stringify(data), { status, headers });
}

function fail(message: string, status = 400) {
  return json({ status: "fail", message }, status);
}

function success(data: object = {}) {
  return json({ status: "success", ...data });
}

function isAdmin(params: Record<string, string>) {
  return params.adminPass === ADMIN_PASSWORD;
}

// ── Duration parsing: "30d", "12h", "1d12h" etc ──
function parseDuration(input: string): number | null {
  const s = input.trim().toLowerCase();

  // "30d12h" format
  const combo = s.match(/^(?:(\d+)d)?(?:(\d+)h)?$/);
  if (combo && (combo[1] || combo[2])) {
    const days = parseInt(combo[1] || "0");
    const hours = parseInt(combo[2] || "0");
    if (days === 0 && hours === 0) return null;
    if (days > 365 || hours > 8760) return null;
    return (days * 24 + hours) * 3600000;
  }

  // plain number = days
  const num = parseInt(s);
  if (!isNaN(num) && num > 0 && num <= 365) {
    return num * 86400000;
  }

  return null;
}

function formatDuration(ms: number): string {
  const totalHours = Math.ceil(ms / 3600000);
  const days = Math.floor(totalHours / 24);
  const hours = totalHours % 24;
  if (days > 0 && hours > 0) return `${days}d ${hours}h`;
  if (days > 0) return `${days}d`;
  return `${hours}h`;
}

function formatRemaining(ms: number): string {
  if (ms <= 0) return "Expired";
  const totalHours = Math.ceil(ms / 3600000);
  const days = Math.floor(totalHours / 24);
  const hours = totalHours % 24;
  if (days > 0 && hours > 0) return `${days}d ${hours}h`;
  if (days > 0) return `${days}d`;
  return `${hours}h`;
}

function formatDateMyanmar(ts: number): string {
  const d = new Date(ts);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const min = String(d.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${min}`;
}

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method === "GET" && path === "/") {
    return new Response(renderHTML(), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // ── Voucher page ──
  if (req.method === "GET" && path === "/voucher") {
    const u = url.searchParams.get("u") || "";
    const p = url.searchParams.get("p") || "";
    const pkg = url.searchParams.get("pkg") || "";
    const exp = url.searchParams.get("exp") || "";
    const created = url.searchParams.get("created") || "";
    return new Response(renderVoucher(u, p, pkg, exp, created), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  let params: Record<string, string> = {};
  try {
    const text = await req.text();
    if (text.startsWith("{")) params = JSON.parse(text);
    else if (text) params = Object.fromEntries(new URLSearchParams(text));
  } catch (_e) {
    /* ignore */
  }

  // ══════════════════════════════════════
  //  PUBLIC ROUTES (APK ခေါ်သုံးတဲ့ endpoint များ)
  // ══════════════════════════════════════

  // ── /login ──
  if (path === "/login") {
    const { username, password, device_id } = params;

    if (!username || !password)
      return fail("Username and password are required");

    const entry = await kv.get(["users", username]);
    if (!entry.value) return fail("User not found");

    const account = entry.value as any;
    const inputHash = await hashPassword(password);

    if (account.password !== inputHash) return fail("Wrong Password");

    if (Date.now() > account.expiry) {
      return json({ status: "expired", message: "Expired" });
    }

    // force_relogin စစ်မယ် — password ပြောင်းထားရင် wrong password ပြမယ်
    if (account.force_relogin) {
      return fail("Wrong Password");
    }

    const userDevId = device_id || "unknown";

    if (account.device_id && account.device_id !== userDevId) {
      return fail("Device Mismatch");
    }

    const remainingMs = account.expiry - Date.now();
    const remainingDays = Math.ceil(remainingMs / 86400000);

    if (!account.device_id && userDevId !== "unknown") {
      account.device_id = userDevId;
    }
    account.force_relogin = false;
    await kv.set(["users", username], account);

    const isReLogin = !!account.device_id && account.device_id === userDevId;

    return json({
      status: isReLogin ? "re_login" : "login",
      user: username,
      expired_date: account.expiry,
      remaining_days: remainingDays,
      device_id: account.device_id,
      message: isReLogin ? "Welcome Back" : "Login Success",
      access: "true",
    });
  }

  // ── /reupload or /edit ──
  if (path === "/reupload" || path === "/edit") {
    const { username, device_id } = params;

    if (!username) return fail("Username is required");

    const entry = await kv.get(["users", username]);
    if (!entry.value) return fail("User not found");

    const acc = entry.value as any;

    // force_relogin ရှိရင် fail
    if (acc.force_relogin) return fail("User not found");

    if (!acc.device_id && device_id) {
      acc.device_id = device_id;
      await kv.set(["users", username], acc);
    }

    return success();
  }

  // ── /checkUsername or /exist ──
  if (path === "/checkUsername" || path === "/exist") {
    const { username } = params;

    if (!username) return fail("Username is required");

    const entry = await kv.get(["users", username]);

    if (!entry.value) return fail("User not found or expired");

    const acc = entry.value as any;

    // force_relogin flag ရှိရင် fail ပြန်ပေးမယ်
    if (acc.force_relogin) {
      return fail("User not found or expired");
    }

    if (acc.expiry > Date.now()) {
      return success();
    }

    return fail("User not found or expired");
  }

  // ══════════════════════════════════════
  //  ADMIN ROUTES (/api/*)
  // ══════════════════════════════════════

  if (path.startsWith("/api/")) {
    if (!isAdmin(params)) {
      return fail("Unauthorized", 401);
    }

    // ── /api/list ──
    if (path === "/api/list") {
      const users: any[] = [];
      for await (const entry of kv.list({ prefix: ["users"] })) {
        users.push(entry.value);
      }
      return success({ data: users });
    }

    // ── /api/create ──
    if (path === "/api/create") {
      const { username, password, duration } = params;

      if (!username || !password || !duration) {
        return fail("username, password, duration are required");
      }

      if (username.length < 3 || username.length > 30) {
        return fail("Username must be 3-30 characters");
      }

      if (password.length < 4) {
        return fail("Password must be at least 4 characters");
      }

      const durationMs = parseDuration(duration);
      if (!durationMs) {
        return fail("Invalid duration. Use: 30d, 12h, 1d12h");
      }

      const existing = await kv.get(["users", username]);
      if (existing.value) {
        return fail("User already exists");
      }

      const hashedPw = await hashPassword(password);
      const now = Date.now();
      const exp = now + durationMs;

      await kv.set(["users", username], {
        username,
        password: hashedPw,
        expiry: exp,
        device_id: null,
        force_relogin: false,
        created_at: now,
        package_label: duration,
      });

      return success({
        voucher: {
          username,
          password,
          package_label: duration,
          expiry: exp,
          created_at: now,
        },
      });
    }

    // ── /api/resetid ──
    if (path === "/api/resetid") {
      const { username } = params;
      if (!username) return fail("Username is required");

      const e = await kv.get(["users", username]);
      if (!e.value) return fail("User not found");

      (e.value as any).device_id = null;
      await kv.set(["users", username], e.value);

      return success();
    }

    // ── /api/extend ──
    if (path === "/api/extend") {
      const { username, duration } = params;
      if (!username || !duration)
        return fail("username and duration are required");

      const durationMs = parseDuration(duration);
      if (!durationMs) {
        return fail("Invalid duration. Use: 30d, 12h, 1d12h");
      }

      const e = await kv.get(["users", username]);
      if (!e.value) return fail("User not found");

      const acc = e.value as any;
      acc.expiry = Math.max(Date.now(), acc.expiry) + durationMs;
      await kv.set(["users", username], acc);

      return success();
    }

    // ── /api/delete ──
    if (path === "/api/delete") {
      const { username } = params;
      if (!username) return fail("Username is required");

      const existing = await kv.get(["users", username]);
      if (!existing.value) return fail("User not found");

      await kv.delete(["users", username]);
      return success();
    }

    // ── /api/changepass ──
    if (path === "/api/changepass") {
      const { username, newPassword } = params;
      if (!username || !newPassword) {
        return fail("username and newPassword are required");
      }

      if (newPassword.length < 4) {
        return fail("Password must be at least 4 characters");
      }

      const e = await kv.get(["users", username]);
      if (!e.value) return fail("User not found");

      const acc = e.value as any;
      acc.password = await hashPassword(newPassword);
      acc.device_id = null;
      acc.force_relogin = true;
      await kv.set(["users", username], acc);

      return success();
    }

    // ── /api/forcelogout ──
    if (path === "/api/forcelogout") {
      const { username } = params;
      if (!username) return fail("Username is required");

      const e = await kv.get(["users", username]);
      if (!e.value) return fail("User not found");

      const acc = e.value as any;
      acc.device_id = null;
      acc.force_relogin = true;
      await kv.set(["users", username], acc);

      return success({ message: "User forcefully logged out" });
    }

    return fail("Unknown API endpoint", 404);
  }

  return new Response("VIP Server", { status: 200 });
});

// ══════════════════════════════════════
//  VOUCHER HTML
// ══════════════════════════════════════

function renderVoucher(
  username: string,
  password: string,
  pkg: string,
  expiry: string,
  created: string
): string {
  const expDate = formatDateMyanmar(parseInt(expiry));
  const createdDate = formatDateMyanmar(parseInt(created));

  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KP VPN VIP Voucher</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #0f172a;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      font-family: 'Segoe UI', Tahoma, sans-serif;
      padding: 20px;
    }
    .voucher-wrap {
      width: 420px;
      max-width: 100%;
    }
    .voucher {
      background: linear-gradient(145deg, #1e293b 0%, #0f172a 50%, #1e293b 100%);
      border: 2px solid #06b6d4;
      border-radius: 20px;
      padding: 0;
      overflow: hidden;
      position: relative;
      box-shadow: 0 0 40px rgba(6, 182, 212, 0.15), 0 20px 60px rgba(0,0,0,0.5);
    }
    .voucher::before {
      content: '';
      position: absolute;
      top: -2px; left: -2px; right: -2px; bottom: -2px;
      background: linear-gradient(45deg, #06b6d4, #8b5cf6, #06b6d4, #8b5cf6);
      border-radius: 20px;
      z-index: -1;
      background-size: 400% 400%;
      animation: shimmer 3s ease infinite;
    }
    @keyframes shimmer {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
    .header {
      background: linear-gradient(135deg, #06b6d4 0%, #8b5cf6 100%);
      padding: 24px 28px;
      text-align: center;
      position: relative;
    }
    .header .crown { font-size: 32px; margin-bottom: 6px; }
    .header h1 {
      color: #fff;
      font-size: 22px;
      font-weight: 800;
      letter-spacing: 3px;
      text-shadow: 0 2px 10px rgba(0,0,0,0.3);
    }
    .header .subtitle {
      color: rgba(255,255,255,0.85);
      font-size: 11px;
      letter-spacing: 5px;
      margin-top: 4px;
      text-transform: uppercase;
    }
    .divider {
      display: flex;
      align-items: center;
      padding: 0 20px;
      margin: 0;
      position: relative;
    }
    .divider::before {
      content: '';
      position: absolute;
      left: -10px; right: -10px;
      height: 1px;
      background: linear-gradient(90deg, transparent, #06b6d4, transparent);
    }
    .circle-left, .circle-right {
      width: 24px; height: 24px;
      background: #0f172a;
      border-radius: 50%;
      position: absolute;
      top: -12px;
    }
    .circle-left { left: -12px; }
    .circle-right { right: -12px; }
    .body { padding: 28px; }
    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 18px;
      margin-bottom: 10px;
      background: rgba(6, 182, 212, 0.06);
      border: 1px solid rgba(6, 182, 212, 0.15);
      border-radius: 12px;
      transition: all 0.3s;
    }
    .info-row:hover {
      background: rgba(6, 182, 212, 0.12);
      border-color: rgba(6, 182, 212, 0.3);
    }
    .info-label {
      color: #94a3b8;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 1px;
      text-transform: uppercase;
    }
    .info-value {
      color: #e2e8f0;
      font-size: 15px;
      font-weight: 700;
      font-family: 'Courier New', monospace;
      letter-spacing: 0.5px;
    }
    .info-value.highlight {
      color: #06b6d4;
      font-size: 16px;
    }
    .footer {
      text-align: center;
      padding: 20px 28px 28px;
      border-top: 1px solid rgba(6, 182, 212, 0.1);
    }
    .footer .thanks {
      color: #8b5cf6;
      font-size: 13px;
      font-weight: 600;
      line-height: 1.8;
    }
    .footer .note {
      color: #64748b;
      font-size: 10px;
      margin-top: 10px;
      letter-spacing: 1px;
    }
    .download-btn {
      display: block;
      margin: 20px auto 0;
      padding: 14px 40px;
      background: linear-gradient(135deg, #06b6d4, #8b5cf6);
      color: #fff;
      border: none;
      border-radius: 12px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      letter-spacing: 1px;
      transition: all 0.3s;
      box-shadow: 0 4px 20px rgba(6, 182, 212, 0.3);
    }
    .download-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 30px rgba(6, 182, 212, 0.5);
    }
    .download-btn:active { transform: translateY(0); }
  </style>
</head>
<body>
  <div class="voucher-wrap">
    <div class="voucher" id="voucherCard">
      <div class="header">
        <div class="crown">👑</div>
        <h1>KP VPN VIP</h1>
        <div class="subtitle">Premium Account Voucher</div>
      </div>

      <div class="divider" style="height:24px;position:relative;">
        <div class="circle-left"></div>
        <div class="circle-right"></div>
      </div>

      <div class="body">
        <div class="info-row">
          <span class="info-label">Username</span>
          <span class="info-value highlight">${escapeHtml(username)}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Password</span>
          <span class="info-value highlight">${escapeHtml(password)}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Package</span>
          <span class="info-value">${escapeHtml(pkg)}</span>
        </div>
        <div class="info-row">
          <span class="info-label">ဝယ်ယူရက်</span>
          <span class="info-value">${escapeHtml(createdDate)}</span>
        </div>
        <div class="info-row">
          <span class="info-label">သက်တမ်းကုန်ဆုံးရက်</span>
          <span class="info-value">${escapeHtml(expDate)}</span>
        </div>
      </div>

      <div class="footer">
        <div class="thanks">ဝယ်ယူအားပေးမှုအတွက်<br>ကျေးဇူးတင်ပါသည် 🙏</div>
        <div class="note">KP VPN — Fast & Secure</div>
      </div>
    </div>

    <button class="download-btn" id="dlBtn" onclick="downloadVoucher()">
      📥 Download Voucher
    </button>
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
  <script>
    async function downloadVoucher() {
      var btn = document.getElementById('dlBtn');
      btn.textContent = 'Generating...';
      btn.disabled = true;
      try {
        var canvas = await html2canvas(document.getElementById('voucherCard'), {
          backgroundColor: '#0f172a',
          scale: 2,
          useCORS: true,
        });
        var link = document.createElement('a');
        link.download = 'KP_VPN_VIP_${escapeHtml(username)}.png';
        link.href = canvas.toDataURL('image/png');
        link.click();
      } catch(e) {
        alert('Download failed: ' + e.message);
      }
      btn.textContent = '📥 Download Voucher';
      btn.disabled = false;
    }
  </script>
</body>
</html>`;
}

// ══════════════════════════════════════
//  ADMIN PANEL HTML
// ══════════════════════════════════════

function renderHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KP VPN - VIP Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background: #0f172a; color: #fff; }
    .glass {
      background: rgba(30, 41, 59, 0.8);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(6, 182, 212, 0.2);
    }
    .btn-glow:hover { box-shadow: 0 0 20px rgba(6, 182, 212, 0.3); }
    input:focus { outline: none; border-color: #06b6d4; box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.2); }
    .status-active { color: #34d399; }
    .status-expired { color: #f87171; }
    .status-kicked { color: #fbbf24; }
  </style>
</head>
<body class="flex justify-center p-4">

  <!-- Auth Screen -->
  <div id="auth" class="w-full max-w-sm mt-20 p-6 glass rounded-2xl">
    <div class="text-center mb-6">
      <div class="text-3xl mb-2">👑</div>
      <h2 class="text-xl text-cyan-400 font-bold">KP VPN Admin</h2>
    </div>
    <input id="pw" type="password" class="w-full p-3 bg-gray-800/50 rounded-xl mb-4 border border-gray-700 transition-all" placeholder="Admin Password">
    <button onclick="login()" class="w-full bg-gradient-to-r from-cyan-600 to-purple-600 p-3 rounded-xl font-bold hover:opacity-90 transition-all btn-glow">LOGIN</button>
    <p id="loginErr" class="text-red-400 text-sm mt-3 hidden text-center"></p>
  </div>

  <!-- App Screen -->
  <div id="app" class="w-full max-w-5xl hidden">

    <!-- Header -->
    <div class="flex justify-between items-center mb-6 mt-2">
      <div class="flex items-center gap-3">
        <span class="text-2xl">👑</span>
        <h1 class="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">KP VPN VIP Manager</h1>
      </div>
      <button onclick="logout()" class="text-red-400 hover:text-red-300 text-sm border border-red-400/30 px-3 py-1 rounded-lg hover:bg-red-400/10 transition-all">Logout</button>
    </div>

    <!-- Create User Form -->
    <div class="glass rounded-2xl p-5 mb-5">
      <h3 class="text-sm text-cyan-400 font-bold mb-4 uppercase tracking-wider">Create New VIP Account</h3>
      <div class="flex gap-3 flex-wrap">
        <input id="u" placeholder="Username (3-30)" class="p-3 bg-gray-800/50 rounded-xl flex-1 min-w-[120px] border border-gray-700 transition-all">
        <input id="p" placeholder="Password (4+)" class="p-3 bg-gray-800/50 rounded-xl flex-1 min-w-[120px] border border-gray-700 transition-all">
        <input id="d" value="30d" placeholder="e.g. 30d, 12h, 1d12h" class="p-3 bg-gray-800/50 rounded-xl w-32 border border-gray-700 transition-all">
        <button id="createBtn" onclick="createUser()" class="bg-gradient-to-r from-green-600 to-emerald-600 p-3 rounded-xl hover:opacity-90 px-6 font-bold transition-all btn-glow">Create</button>
      </div>
      <p class="text-gray-500 text-xs mt-2">Duration format: 30d = 30 days, 12h = 12 hours, 1d12h = 1 day 12 hours</p>
    </div>

    <p id="msg" class="text-sm mb-3 hidden"></p>

    <!-- Users Table -->
    <div class="glass rounded-2xl overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-gray-900/50 text-left">
          <tr>
            <th class="p-4 text-cyan-400 font-bold text-xs uppercase tracking-wider">User</th>
            <th class="p-4 text-cyan-400 font-bold text-xs uppercase tracking-wider">Expires</th>
            <th class="p-4 text-cyan-400 font-bold text-xs uppercase tracking-wider">Remaining</th>
            <th class="p-4 text-cyan-400 font-bold text-xs uppercase tracking-wider">Device</th>
            <th class="p-4 text-cyan-400 font-bold text-xs uppercase tracking-wider">Status</th>
            <th class="p-4 text-cyan-400 font-bold text-xs uppercase tracking-wider text-right">Actions</th>
          </tr>
        </thead>
        <tbody id="list"></tbody>
      </table>
    </div>

    <!-- Stats -->
    <div class="flex gap-4 mt-5 flex-wrap">
      <div class="glass rounded-xl p-4 flex-1 min-w-[150px] text-center">
        <div class="text-2xl font-bold text-cyan-400" id="totalUsers">0</div>
        <div class="text-xs text-gray-400 mt-1">Total Users</div>
      </div>
      <div class="glass rounded-xl p-4 flex-1 min-w-[150px] text-center">
        <div class="text-2xl font-bold text-green-400" id="activeUsers">0</div>
        <div class="text-xs text-gray-400 mt-1">Active</div>
      </div>
      <div class="glass rounded-xl p-4 flex-1 min-w-[150px] text-center">
        <div class="text-2xl font-bold text-red-400" id="expiredUsers">0</div>
        <div class="text-xs text-gray-400 mt-1">Expired</div>
      </div>
    </div>

  </div>

  <!-- Voucher Modal -->
  <div id="voucherModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm hidden flex items-center justify-center z-50 p-4">
    <div class="glass rounded-2xl p-6 max-w-md w-full">
      <div class="flex justify-between items-center mb-4">
        <h3 class="text-cyan-400 font-bold">Account Created!</h3>
        <button onclick="closeVoucher()" class="text-gray-400 hover:text-white text-xl">&times;</button>
      </div>
      <div id="voucherPreview" class="bg-gradient-to-br from-gray-900 to-gray-800 rounded-xl p-5 border border-cyan-500/30 mb-4">
        <div class="text-center mb-4">
          <div class="text-2xl mb-1">👑</div>
          <div class="text-cyan-400 font-bold text-lg">KP VPN VIP</div>
        </div>
        <div class="space-y-3 text-sm">
          <div class="flex justify-between"><span class="text-gray-400">Username</span><span class="text-cyan-300 font-mono font-bold" id="vUser"></span></div>
          <div class="flex justify-between"><span class="text-gray-400">Password</span><span class="text-cyan-300 font-mono font-bold" id="vPass"></span></div>
          <div class="flex justify-between"><span class="text-gray-400">Package</span><span class="text-white font-bold" id="vPkg"></span></div>
          <div class="flex justify-between"><span class="text-gray-400">ဝယ်ယူရက်</span><span class="text-white" id="vCreated"></span></div>
          <div class="flex justify-between"><span class="text-gray-400">သက်တမ်းကုန်ဆုံးရက်</span><span class="text-white" id="vExp"></span></div>
        </div>
        <div class="text-center mt-4 pt-3 border-t border-gray-700">
          <div class="text-purple-400 text-xs">ဝယ်ယူအားပေးမှုအတွက် ကျေးဇူးတင်ပါသည် 🙏</div>
        </div>
      </div>
      <div class="flex gap-3">
        <button onclick="copyVoucherText()" class="flex-1 bg-purple-600 p-3 rounded-xl font-bold hover:bg-purple-700 transition-all text-sm">📋 Copy Text</button>
        <a id="voucherLink" target="_blank" class="flex-1 bg-gradient-to-r from-cyan-600 to-purple-600 p-3 rounded-xl font-bold hover:opacity-90 transition-all text-center text-sm text-white no-underline">📥 Download Image</a>
      </div>
    </div>
  </div>

<script>
let T = sessionStorage.getItem("t");
if (T) show();

function esc(s) {
  var d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function fmtDate(ts) {
  var d = new Date(ts);
  return d.getFullYear() + '-' +
    String(d.getMonth()+1).padStart(2,'0') + '-' +
    String(d.getDate()).padStart(2,'0') + ' ' +
    String(d.getHours()).padStart(2,'0') + ':' +
    String(d.getMinutes()).padStart(2,'0');
}

function fmtRemaining(ms) {
  if (ms <= 0) return '<span class="text-red-400">Expired</span>';
  var totalH = Math.ceil(ms / 3600000);
  var days = Math.floor(totalH / 24);
  var hours = totalH % 24;
  if (days > 0 && hours > 0) return days + 'd ' + hours + 'h';
  if (days > 0) return days + 'd';
  return hours + 'h';
}

function showMsg(text, isError) {
  var el = document.getElementById("msg");
  el.textContent = text;
  el.className = "text-sm mb-3 px-4 py-2 rounded-xl " + (isError ? "text-red-400 bg-red-400/10" : "text-green-400 bg-green-400/10");
  el.classList.remove("hidden");
  setTimeout(function() { el.classList.add("hidden"); }, 3000);
}

async function login() {
  T = document.getElementById("pw").value;
  if (!T) return;
  try {
    var r = await fetch("/api/list", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ adminPass: T })
    });
    var j = await r.json();
    if (j.status === "success") {
      sessionStorage.setItem("t", T);
      show();
    } else {
      var errEl = document.getElementById("loginErr");
      errEl.textContent = "Wrong password!";
      errEl.classList.remove("hidden");
    }
  } catch (e) {
    var errEl = document.getElementById("loginErr");
    errEl.textContent = "Connection failed";
    errEl.classList.remove("hidden");
  }
}

function logout() {
  sessionStorage.removeItem("t");
  location.reload();
}

function show() {
  document.getElementById("auth").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  load();
}

async function api(endpoint, data) {
  if (!data) data = {};
  data.adminPass = T;
  try {
    var r = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });
    var j = await r.json();
    if (j.status !== "success") {
      showMsg(j.message || "Operation failed", true);
      return null;
    }
    return j;
  } catch (e) {
    showMsg("Connection failed: " + e.message, true);
    return null;
  }
}

var lastVoucher = null;

async function createUser() {
  var btn = document.getElementById("createBtn");
  btn.disabled = true;
  btn.textContent = "Creating...";
  try {
    var username = document.getElementById("u").value.trim();
    var password = document.getElementById("p").value.trim();
    var duration = document.getElementById("d").value.trim();
    if (!username || !password) { showMsg("Username and password are required", true); return; }
    if (username.length < 3 || username.length > 30) { showMsg("Username must be 3-30 characters", true); return; }
    if (password.length < 4) { showMsg("Password must be at least 4 characters", true); return; }
    if (!duration) { showMsg("Duration is required", true); return; }

    var result = await api("/api/create", { username: username, password: password, duration: duration });
    if (result) {
      lastVoucher = { username: username, password: password, pkg: duration, exp: result.voucher.expiry, created: result.voucher.created_at };
      showVoucher(lastVoucher);
      document.getElementById("u").value = "";
      document.getElementById("p").value = "";
      document.getElementById("d").value = "30d";
      await load();
    }
  } catch (e) { showMsg("Error: " + e.message, true); }
  finally { btn.disabled = false; btn.textContent = "Create"; }
}

function showVoucher(v) {
  document.getElementById("vUser").textContent = v.username;
  document.getElementById("vPass").textContent = v.password;
  document.getElementById("vPkg").textContent = v.pkg;
  document.getElementById("vCreated").textContent = fmtDate(v.created);
  document.getElementById("vExp").textContent = fmtDate(v.exp);

  var link = document.getElementById("voucherLink");
  link.href = "/voucher?u=" + encodeURIComponent(v.username) +
    "&p=" + encodeURIComponent(v.password) +
    "&pkg=" + encodeURIComponent(v.pkg) +
    "&exp=" + v.exp +
    "&created=" + v.created;

  document.getElementById("voucherModal").classList.remove("hidden");
}

function closeVoucher() {
  document.getElementById("voucherModal").classList.add("hidden");
}

function copyVoucherText() {
  if (!lastVoucher) return;
  var text = "👑 KP VPN VIP 👑\\n" +
    "━━━━━━━━━━━━━━━━\\n" +
    "Username: " + lastVoucher.username + "\\n" +
    "Password: " + lastVoucher.password + "\\n" +
    "Package: " + lastVoucher.pkg + "\\n" +
    "ဝယ်ယူရက်: " + fmtDate(lastVoucher.created) + "\\n" +
    "သက်တမ်းကုန်ဆုံးရက်: " + fmtDate(lastVoucher.exp) + "\\n" +
    "━━━━━━━━━━━━━━━━\\n" +
    "ဝယ်ယူအားပေးမှုအတွက် ကျေးဇူးတင်ပါသည် 🙏";

  navigator.clipboard.writeText(text).then(function() {
    showMsg("Copied to clipboard!", false);
  }).catch(function() {
    showMsg("Copy failed", true);
  });
}

async function resetId(username) {
  if (!confirm("Reset device ID for " + username + "?")) return;
  var result = await api("/api/resetid", { username: username });
  if (result) { showMsg("Device ID reset", false); load(); }
}

async function extend(username) {
  var duration = prompt("Duration to extend? (e.g. 30d, 12h, 1d12h)", "30d");
  if (!duration) return;
  var result = await api("/api/extend", { username: username, duration: duration });
  if (result) { showMsg("Extended: " + duration, false); load(); }
}

async function deleteUser(username) {
  if (!confirm("Delete user " + username + "?")) return;
  var result = await api("/api/delete", { username: username });
  if (result) { showMsg("User deleted", false); load(); }
}

async function changePass(username) {
  var newPassword = prompt("New password for " + username + ":");
  if (!newPassword) return;
  if (newPassword.length < 4) { showMsg("Password must be at least 4 characters", true); return; }
  var result = await api("/api/changepass", { username: username, newPassword: newPassword });
  if (result) { showMsg("Password changed & user kicked", false); load(); }
}

async function forceLogout(username) {
  if (!confirm("Force logout " + username + "?")) return;
  var result = await api("/api/forcelogout", { username: username });
  if (result) { showMsg("User force logged out", false); load(); }
}

async function load() {
  var r = await api("/api/list");
  if (!r) return;
  var tbody = document.getElementById("list");
  tbody.innerHTML = "";

  var total = 0, active = 0, expired = 0;

  if (!r.data || r.data.length === 0) {
    tbody.innerHTML = "<tr><td colspan='6' class='p-6 text-center text-gray-500'>No users yet</td></tr>";
  } else {
    r.data.sort(function(a, b) { return b.expiry - a.expiry; }).forEach(function(u) {
      total++;
      var remaining = u.expiry - Date.now();
      var isExpired = remaining <= 0;
      if (isExpired) expired++; else active++;

      var dev = u.device_id ? "<span class='text-cyan-300'>🔒 Locked</span>" : "<span class='text-gray-500'>—</span>";

      var statusText;
      if (u.force_relogin) {
        statusText = "<span class='status-kicked'>⚠ Kicked</span>";
      } else if (isExpired) {
        statusText = "<span class='status-expired'>✗ Expired</span>";
      } else {
        statusText = "<span class='status-active'>✓ Active</span>";
      }

      var tr = document.createElement("tr");
      tr.className = "border-b border-gray-800/50 hover:bg-gray-800/30 transition-all";
      tr.innerHTML =
        "<td class='p-4 font-bold text-white'>" + esc(u.username) + "</td>" +
        "<td class='p-4 text-gray-300 text-xs'>" + fmtDate(u.expiry) + "</td>" +
        "<td class='p-4 font-mono text-sm'>" + fmtRemaining(remaining) + "</td>" +
        "<td class='p-4 text-xs'>" + dev + "</td>" +
        "<td class='p-4 text-xs font-bold'>" + statusText + "</td>" +
        "<td class='p-4 text-right'></td>";

      var actionTd = tr.querySelector("td:last-child");
      var actions = [
        { text: "Reset", cls: "text-yellow-400 hover:bg-yellow-400/10", fn: function() { resetId(u.username); } },
        { text: "Renew", cls: "text-blue-400 hover:bg-blue-400/10", fn: function() { extend(u.username); } },
        { text: "Pass", cls: "text-purple-400 hover:bg-purple-400/10", fn: function() { changePass(u.username); } },
        { text: "Kick", cls: "text-orange-400 hover:bg-orange-400/10", fn: function() { forceLogout(u.username); } },
        { text: "Del", cls: "text-red-400 hover:bg-red-400/10", fn: function() { deleteUser(u.username); } },
      ];
      actions.forEach(function(a) {
        var btn = document.createElement("button");
        btn.textContent = a.text;
        btn.className = "text-xs px-2 py-1 rounded-lg mr-1 transition-all " + a.cls;
        btn.onclick = a.fn;
        actionTd.appendChild(btn);
      });

      tbody.appendChild(tr);
    });
  }

  document.getElementById("totalUsers").textContent = total;
  document.getElementById("activeUsers").textContent = active;
  document.getElementById("expiredUsers").textContent = expired;
}
</script>
</body>
</html>`;
}
