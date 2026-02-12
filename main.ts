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

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;

  // ── OPTIONS Preflight ──
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // ── GET / → Admin Panel HTML (body မဖတ်ဘူး) ──
  if (req.method === "GET" && path === "/") {
    return new Response(renderHTML(), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // ── Parse params (POST requests only) ──
  let params: Record<string, string> = {};
  try {
    const text = await req.text();
    if (text.startsWith("{")) params = JSON.parse(text);
    else if (text) params = Object.fromEntries(new URLSearchParams(text));
  } catch (_e) {
    /* ignore */
  }

  // ══════════════════════════════════════
  //  PUBLIC ROUTES
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

    const userDevId = device_id || "unknown";

    if (account.device_id && account.device_id !== userDevId) {
      return fail("Device Mismatch");
    }

    const remainingDays = Math.ceil(
      (account.expiry - Date.now()) / 86400000
    );

    // ပထမ login - device_id bind လုပ်ပေးမယ်
    if (!account.device_id && userDevId !== "unknown") {
      account.device_id = userDevId;
      await kv.set(["users", username], account);
    }

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

    if (entry.value && (entry.value as any).expiry > Date.now()) {
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
      const { username, password, days } = params;

      if (!username || !password || !days) {
        return fail("username, password, days are required");
      }

      if (username.length < 3 || username.length > 30) {
        return fail("Username must be 3-30 characters");
      }

      if (password.length < 4) {
        return fail("Password must be at least 4 characters");
      }

      const daysNum = parseInt(days);
      if (isNaN(daysNum) || daysNum <= 0 || daysNum > 365) {
        return fail("Days must be 1-365");
      }

      const existing = await kv.get(["users", username]);
      if (existing.value) {
        return fail("User already exists");
      }

      const hashedPw = await hashPassword(password);
      const exp = Date.now() + daysNum * 86400000;

      await kv.set(["users", username], {
        username,
        password: hashedPw,
        expiry: exp,
        device_id: null,
      });

      return success();
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
      const { username, days } = params;
      if (!username || !days) return fail("username and days are required");

      const daysNum = parseInt(days);
      if (isNaN(daysNum) || daysNum <= 0 || daysNum > 365) {
        return fail("Days must be 1-365");
      }

      const e = await kv.get(["users", username]);
      if (!e.value) return fail("User not found");

      const acc = e.value as any;
      acc.expiry = Math.max(Date.now(), acc.expiry) + daysNum * 86400000;
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

      (e.value as any).password = await hashPassword(newPassword);
      await kv.set(["users", username], e.value);

      return success();
    }

    return fail("Unknown API endpoint", 404);
  }

  // ── Fallback ──
  return new Response("VIP Server", { status: 200 });
});

// ══════════════════════════════════════
//  ADMIN PANEL HTML
// ══════════════════════════════════════

function renderHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VIP Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>body{background:#111827;color:#fff}</style>
</head>
<body class="flex justify-center p-5">

  <!-- Auth Screen -->
  <div id="auth" class="w-full max-w-sm mt-10 p-5 bg-gray-800 rounded">
    <h2 class="text-xl mb-3 text-cyan-400 font-bold">Admin Login</h2>
    <input id="pw" type="password" class="w-full p-2 bg-gray-700 rounded mb-3" placeholder="Password">
    <button onclick="login()" class="w-full bg-cyan-600 p-2 rounded hover:bg-cyan-700">LOGIN</button>
    <p id="loginErr" class="text-red-400 text-sm mt-2 hidden"></p>
  </div>

  <!-- App Screen -->
  <div id="app" class="w-full max-w-4xl hidden">
    <div class="flex justify-between mb-5">
      <h1 class="text-2xl font-bold text-cyan-400">VIP MANAGER</h1>
      <button onclick="logout()" class="text-red-400 hover:text-red-300">Logout</button>
    </div>

    <!-- Create User Form -->
    <div class="flex gap-2 mb-5 flex-wrap">
      <input id="u" placeholder="Username (3-30)" class="p-2 bg-gray-800 rounded flex-1 min-w-[100px] border border-gray-700">
      <input id="p" placeholder="Password (4+)" class="p-2 bg-gray-800 rounded flex-1 min-w-[100px] border border-gray-700">
      <input id="d" type="number" value="30" min="1" max="365" class="p-2 bg-gray-800 rounded w-20 border border-gray-700">
      <button id="createBtn" onclick="createUser()" class="bg-green-600 p-2 rounded hover:bg-green-700 px-4">Create</button>
    </div>

    <p id="msg" class="text-sm mb-3 hidden"></p>

    <!-- Users Table -->
    <table class="w-full text-sm bg-gray-800 rounded overflow-hidden">
      <thead class="bg-gray-900 text-left">
        <tr>
          <th class="p-3">User</th>
          <th class="p-3">Expires</th>
          <th class="p-3">Device</th>
          <th class="p-3 text-right">Action</th>
        </tr>
      </thead>
      <tbody id="list"></tbody>
    </table>
  </div>

<script>
let T = sessionStorage.getItem("t");
if (T) show();

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function showMsg(text, isError) {
  const el = document.getElementById("msg");
  el.textContent = text;
  el.className = "text-sm mb-3 " + (isError ? "text-red-400" : "text-green-400");
  el.classList.remove("hidden");
  setTimeout(function() { el.classList.add("hidden"); }, 3000);
}

async function login() {
  T = document.getElementById("pw").value;
  if (!T) return;

  try {
    const r = await fetch("/api/list", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ adminPass: T })
    });
    const j = await r.json();
    if (j.status === "success") {
      sessionStorage.setItem("t", T);
      show();
    } else {
      const errEl = document.getElementById("loginErr");
      errEl.textContent = "Wrong password!";
      errEl.classList.remove("hidden");
    }
  } catch (e) {
    const errEl = document.getElementById("loginErr");
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
    const r = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });
    const j = await r.json();
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

async function createUser() {
  var btn = document.getElementById("createBtn");
  btn.disabled = true;
  btn.textContent = "Creating...";

  try {
    var username = document.getElementById("u").value.trim();
    var password = document.getElementById("p").value.trim();
    var days = document.getElementById("d").value.trim();

    if (!username || !password) {
      showMsg("Username and password are required", true);
      return;
    }

    if (username.length < 3 || username.length > 30) {
      showMsg("Username must be 3-30 characters", true);
      return;
    }

    if (password.length < 4) {
      showMsg("Password must be at least 4 characters", true);
      return;
    }

    if (!days || isNaN(parseInt(days)) || parseInt(days) <= 0) {
      showMsg("Days must be a valid number", true);
      return;
    }

    var result = await api("/api/create", { username: username, password: password, days: days });
    if (result) {
      showMsg("User '" + username + "' created successfully!", false);
      document.getElementById("u").value = "";
      document.getElementById("p").value = "";
      document.getElementById("d").value = "30";
      await load();
    }
  } catch (e) {
    showMsg("Error: " + e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Create";
  }
}

async function resetId(username) {
  if (!confirm("Reset device ID for " + username + "?")) return;
  var result = await api("/api/resetid", { username: username });
  if (result) {
    showMsg("Device ID reset", false);
    load();
  }
}

async function extend(username) {
  var days = prompt("How many days to extend?", "30");
  if (!days) return;
  var result = await api("/api/extend", { username: username, days: days });
  if (result) {
    showMsg("Extended " + days + " days", false);
    load();
  }
}

async function deleteUser(username) {
  if (!confirm("Delete user " + username + "?")) return;
  var result = await api("/api/delete", { username: username });
  if (result) {
    showMsg("User deleted", false);
    load();
  }
}

async function changePass(username) {
  var newPassword = prompt("New password for " + username + ":");
  if (!newPassword) return;
  if (newPassword.length < 4) {
    showMsg("Password must be at least 4 characters", true);
    return;
  }
  var result = await api("/api/changepass", { username: username, newPassword: newPassword });
  if (result) {
    showMsg("Password changed", false);
  }
}

async function load() {
  var r = await api("/api/list");
  if (!r) return;

  var tbody = document.getElementById("list");
  tbody.innerHTML = "";

  if (!r.data || r.data.length === 0) {
    tbody.innerHTML = "<tr><td colspan='4' class='p-3 text-center text-gray-500'>No users yet</td></tr>";
    return;
  }

  r.data.sort(function(a, b) { return a.expiry - b.expiry; }).forEach(function(u) {
    var d = Math.ceil((u.expiry - Date.now()) / 86400000);
    var isExpired = d <= 0;
    var daysText = isExpired ? "<span class='text-red-400'>Expired</span>" : d + "d";
    var dev = u.device_id
      ? "<span class='text-cyan-300'>Locked</span>"
      : "<span class='text-gray-500'>--</span>";

    var tr = document.createElement("tr");
    tr.className = "border-b border-gray-700";
    tr.innerHTML =
      "<td class='p-3 font-bold'>" + esc(u.username) + "</td>" +
      "<td class='p-3'>" + new Date(u.expiry).toLocaleDateString() + " (" + daysText + ")</td>" +
      "<td class='p-3'>" + dev + "</td>" +
      "<td class='p-3 text-right'></td>";

    var actionTd = tr.querySelector("td:last-child");

    var btnReset = document.createElement("button");
    btnReset.textContent = "Reset";
    btnReset.className = "text-yellow-400 mr-2 hover:text-yellow-300";
    btnReset.onclick = function() { resetId(u.username); };

    var btnRenew = document.createElement("button");
    btnRenew.textContent = "Renew";
    btnRenew.className = "text-blue-400 mr-2 hover:text-blue-300";
    btnRenew.onclick = function() { extend(u.username); };

    var btnPass = document.createElement("button");
    btnPass.textContent = "Pass";
    btnPass.className = "text-purple-400 mr-2 hover:text-purple-300";
    btnPass.onclick = function() { changePass(u.username); };

    var btnDel = document.createElement("button");
    btnDel.textContent = "Del";
    btnDel.className = "text-red-400 hover:text-red-300";
    btnDel.onclick = function() { deleteUser(u.username); };

    actionTd.appendChild(btnReset);
    actionTd.appendChild(btnRenew);
    actionTd.appendChild(btnPass);
    actionTd.appendChild(btnDel);

    tbody.appendChild(tr);
  });
}
</script>
</body>
</html>`;
}
