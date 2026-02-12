const kv = await Deno.openKv();
const ADMIN_PASSWORD = "admin"; 
Deno.serve(async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS"
  };
  if (method === "OPTIONS") return new Response(null, { headers });
  if (method === "GET" && path === "/") {
    return new Response(renderHTML(), { headers: { "content-type": "text/html; charset=utf-8" } });
  }
  let params = {};
  try {
    const text = await req.text();
    if (text.startsWith("{")) {
        params = JSON.parse(text);
    } else {
        const urlParams = new URLSearchParams(text);
        params = Object.fromEntries(urlParams);
    }
  } catch (e) { }
  if (path.includes("login")) {
    const { username, password, device_id } = params;
    const userDeviceId = device_id || "unknown_device";
    const entry = await kv.get(["users", username]);
    if (!entry.value) {
      return new Response(JSON.stringify({ status: "fail", message: "User not found" }), { headers });
    }
    const account = entry.value;
    if (account.password !== password) {
      return new Response(JSON.stringify({ status: "fail", message: "Wrong Password" }), { headers });
    }
    if (Date.now() > account.expiry) {
      return new Response(JSON.stringify({ status: "expired", message: "Account Expired" }), { headers });
    }
    if (account.device_id && account.device_id !== userDeviceId) {
       return new Response(JSON.stringify({ status: "fail", message: "Device Mismatch! Contact Admin." }), { headers });
    }
    if (!account.device_id) {
       account.device_id = userDeviceId;
       await kv.set(["users", username], account);
    }
    const remainingDays = Math.ceil((account.expiry - Date.now()) / (24 * 60 * 60 * 1000));
    const responseData = {
      "status": "login",
      "user": username,
      "expired_date": remainingDays.toString(), 
      "access": "true",
      "message": "Login Success"
    };
    return new Response(JSON.stringify(responseData), { headers });
  }
  if (path.includes("checkUsername") || path.includes("exist")) {
     const { username } = params;
     const entry = await kv.get(["users", username]);
     if (entry.value && entry.value.expiry > Date.now()) {
         return new Response(JSON.stringify({"status": "success"}), { headers });
     } else {
         return new Response(JSON.stringify({"status": "fail"}), { headers });
     }
  }
  if (path.includes("reupload") || path.includes("edit")) {
     return new Response(JSON.stringify({"status": "success"}), { headers });
  }
  if (path.includes("delete")) {
     const username = params.usernameToDelete || params.username;
     if(username) await kv.delete(["users", username]);
     return new Response(JSON.stringify({"status": "success"}), { headers });
  }
  if (path.startsWith("/api/")) {
    if (params.adminPass !== ADMIN_PASSWORD) return new Response(JSON.stringify({ status: "fail" }), { headers });
    if (path === "/api/list") {
        const users = [];
        for await (const entry of kv.list({ prefix: ["users"] })) users.push(entry.value);
        return new Response(JSON.stringify({ status: "success", data: users }), { headers });
    }
    if (path === "/api/create") {
        const { username, password, days } = params;
        const existing = await kv.get(["users", username]);
        if (existing.value) return new Response(JSON.stringify({ status: "fail", message: "Exists" }), { headers });
        const expiryDate = Date.now() + (parseInt(days) * 24 * 60 * 60 * 1000);
        await kv.set(["users", username], { username, password, expiry: expiryDate, device_id: null, status: "active" });
        return new Response(JSON.stringify({ status: "success" }), { headers });
    }
    if (path === "/api/resetid") {
        const { username } = params;
        const entry = await kv.get(["users", username]);
        if(entry.value) {
            const acc = entry.value;
            acc.device_id = null; 
            await kv.set(["users", username], acc);
        }
        return new Response(JSON.stringify({ status: "success" }), { headers });
    }
    if (path === "/api/extend") {
        const { username, days } = params;
        const entry = await kv.get(["users", username]);
        if (entry.value) {
            const acc = entry.value;
            const current = acc.expiry > Date.now() ? acc.expiry : Date.now();
            acc.expiry = current + (parseInt(days) * 24 * 60 * 60 * 1000);
            await kv.set(["users", username], acc);
        }
        return new Response(JSON.stringify({ status: "success" }), { headers });
    }
    if (path === "/api/delete") {
        await kv.delete(["users", params.username]);
        return new Response(JSON.stringify({ status: "success" }), { headers });
    }
  }
  return new Response("VIP Server", { status: 404 });
});
function renderHTML() {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIP Manager (Device Lock)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>body{background:#0f172a;color:white;}</style>
</head>
<body class="flex justify-center min-h-screen p-4">
    <div id="login" class="w-full max-w-sm mt-20 text-center">
        <h2 class="text-2xl font-bold mb-4 text-cyan-400">Admin Panel</h2>
        <input type="password" id="pass" class="w-full p-3 rounded bg-slate-800 border border-slate-600 mb-4" placeholder="Password">
        <button onclick="login()" class="w-full bg-cyan-600 p-3 rounded font-bold">ENTER</button>
    </div>
    <div id="panel" class="w-full max-w-5xl hidden">
        <div class="flex justify-between items-center mb-8 mt-4">
            <h1 class="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">VIP MANAGER</h1>
            <button onclick="logout()" class="text-red-400">Logout</button>
        </div>
        <div class="bg-slate-800 p-4 rounded-xl mb-6 flex gap-2 flex-col md:flex-row">
            <input id="u" placeholder="Username" class="p-3 bg-slate-700 rounded flex-1">
            <input id="p" placeholder="Password" class="p-3 bg-slate-700 rounded flex-1">
            <input id="d" type="number" value="30" placeholder="Days" class="p-3 bg-slate-700 rounded w-24">
            <button onclick="create()" class="bg-green-600 px-6 py-3 rounded font-bold">Create</button>
        </div>
        <div class="overflow-x-auto bg-slate-800 rounded-xl">
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-900 text-slate-400">
                    <tr>
                        <th class="p-3">User</th>
                        <th class="p-3">Pass</th>
                        <th class="p-3">Expires</th>
                        <th class="p-3">Device ID</th>
                        <th class="p-3 text-right">Actions</th>
                    </tr>
                </thead>
                <tbody id="list"></tbody>
            </table>
        </div>
    </div>
    <script>
        let TOKEN = localStorage.getItem("t");
        if(TOKEN) show();
        function login() { TOKEN = document.getElementById("pass").value; localStorage.setItem("t", TOKEN); show(); }
        function logout() { localStorage.removeItem("t"); location.reload(); }
        function show() { document.getElementById("login").classList.add("hidden"); document.getElementById("panel").classList.remove("hidden"); load(); }
        async function req(ep, data) {
            data.adminPass = TOKEN;
            const res = await fetch(ep, { method: "POST", body: JSON.stringify(data) });
            return await res.json();
        }
        async function load() {
            const res = await req("/api/list", {});
            if(res.status!=="success") return;
            const tb = document.getElementById("list"); tb.innerHTML = "";
            res.data.sort((a,b)=>a.expiry-b.expiry).forEach(u => {
                const days = Math.ceil((u.expiry - Date.now())/86400000);
                const dev = u.device_id ? u.device_id.substring(0,8)+"..." : "<span class='text-green-400'>Free</span>";
                const row = \`
                <tr class="border-b border-slate-700 hover:bg-slate-700">
                    <td class="p-3 font-bold">\${u.username}</td>
                    <td class="p-3 text-slate-400">\${u.password}</td>
                    <td class="p-3">\${new Date(u.expiry).toLocaleDateString()} (\${days}d)</td>
                    <td class="p-3 text-xs font-mono">\${dev}</td>
                    <td class="p-3 text-right space-x-1">
                        <button onclick="reset('\${u.username}')" class="bg-yellow-600 text-white px-2 py-1 rounded text-xs" title="Reset Device">Reset ID</button>
                        <button onclick="ext('\${u.username}')" class="bg-blue-600 text-white px-2 py-1 rounded text-xs">Renew</button>
                        <button onclick="del('\${u.username}')" class="bg-red-600 text-white px-2 py-1 rounded text-xs">Del</button>
                    </td>
                </tr>\`;
                tb.innerHTML += row;
            });
        }
        async function create() { await req("/api/create", { username: document.getElementById("u").value, password: document.getElementById("p").value, days: document.getElementById("d").value }); document.getElementById("u").value=""; load(); }
        async function ext(u) { const d = prompt("Days:", "30"); if(d) { await req("/api/extend", {username:u, days:d}); load(); } }
        async function del(u) { if(confirm("Del?")) { await req("/api/delete", {username:u}); load(); } }
        async function reset(u) { if(confirm("Reset Device ID for "+u+"?")) { await req("/api/resetid", {username:u}); load(); } }
    </script>
</body>
</html>
  `;
}
