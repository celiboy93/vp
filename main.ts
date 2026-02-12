/**
 * VIP VPN Server System (Database + Admin Panel + API)
 * 
 * 1. Login API
 * 2. Check User API
 * 3. Reupload API
 * 4. Delete API
 * 5. Web Admin Panel
 */

const kv = await Deno.openKv();

// ==========================================
// ADMIN PASSWORD (ဒီနေရာမှာ ကိုယ်ကြိုက်တာ ပြောင်းပါ)
// ==========================================
const ADMIN_PASSWORD = "admin"; 
// ==========================================

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // CORS Headers (Error မတက်အောင်)
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS"
  };

  // Preflight request
  if (method === "OPTIONS") return new Response(null, { headers });

  // --------------------------------------------------------
  // 1. ADMIN PANEL (WEB UI) - Browser မှာဖွင့်ရင် မြင်ရမယ့်အပိုင်း
  // --------------------------------------------------------
  if (method === "GET" && path === "/") {
    return new Response(renderHTML(), {
      headers: { "content-type": "text/html; charset=utf-8" }
    });
  }

  // --------------------------------------------------------
  // Helper: Request Body ကို ဖတ်ရန် (JSON or Form Data)
  // --------------------------------------------------------
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

  // --------------------------------------------------------
  // 2. APK LINKS (App က လှမ်းခေါ်မယ့် လမ်းကြောင်း ၄ ခု)
  // --------------------------------------------------------

  // [LINK 1] LOGIN
  // APK က username နဲ့ password ပို့လာရင် စစ်ပေးမယ်
  if (path.includes("login")) {
    const { username, password } = params;
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

    // လက်ကျန်ရက် တွက်မယ်
    const remainingDays = Math.ceil((account.expiry - Date.now()) / (24 * 60 * 60 * 1000));

    // APK ပုံစံအတိုင်း ပြန်ပို့မယ်
    const responseData = {
      "status": "login",
      "user": username,
      "expired_date": remainingDays.toString(), // APK က String လိုချင်လို့
      "access": "true",
      "message": "Login Success"
    };
    return new Response(JSON.stringify(responseData), { headers });
  }

  // [LINK 2] CHECK USER / EXIST
  // APK ဖွင့်ဖွင့်ချင်း အကောင့်ရှိမရှိ/သက်တမ်းကျန်မကျန် စစ်တဲ့နေရာ
  if (path.includes("checkUsername") || path.includes("exist") || path.includes("user_exit")) {
     const { username } = params;
     const entry = await kv.get(["users", username]);
     
     // အကောင့်ရှိပြီး သက်တမ်းကျန်မှ Success ပြန်မယ်
     if (entry.value && entry.value.expiry > Date.now()) {
         return new Response(JSON.stringify({"status": "success"}), { headers });
     } else {
         return new Response(JSON.stringify({"status": "fail"}), { headers });
     }
  }

  // [LINK 3] REUPLOAD / EDIT
  // App က Device ID တို့ Date တို့ ပြန်ပို့တဲ့နေရာ (Error မတက်အောင် Success ပဲ ပြန်လိုက်မယ်)
  if (path.includes("reupload") || path.includes("edit")) {
     return new Response(JSON.stringify({"status": "success", "message": "Updated"}), { headers });
  }

  // [LINK 4] DELETE
  // App ထဲကနေ အကောင့်ဖျက်ချင်ရင် သုံးတဲ့နေရာ
  if (path.includes("delete")) {
     const username = params.usernameToDelete || params.username;
     if (username) {
        await kv.delete(["users", username]);
     }
     return new Response(JSON.stringify({"status": "success", "message": "Deleted"}), { headers });
  }

  // --------------------------------------------------------
  // 3. INTERNAL API (Admin Panel က သုံးဖို့)
  // --------------------------------------------------------
  if (path.startsWith("/api/")) {
    if (params.adminPass !== ADMIN_PASSWORD) {
        return new Response(JSON.stringify({ status: "fail", message: "Wrong Admin Password" }), { headers });
    }

    // List Users
    if (path === "/api/list") {
        const users = [];
        for await (const entry of kv.list({ prefix: ["users"] })) {
          users.push(entry.value);
        }
        return new Response(JSON.stringify({ status: "success", data: users }), { headers });
    }

    // Create User
    if (path === "/api/create") {
        const { username, password, days } = params;
        const existing = await kv.get(["users", username]);
        if (existing.value) return new Response(JSON.stringify({ status: "fail", message: "User exists" }), { headers });

        const expiryDate = Date.now() + (parseInt(days) * 24 * 60 * 60 * 1000);
        await kv.set(["users", username], { username, password, expiry: expiryDate, status: "active" });
        return new Response(JSON.stringify({ status: "success" }), { headers });
    }

    // Extend User
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

    // Delete User (Admin)
    if (path === "/api/delete") {
        await kv.delete(["users", params.username]);
        return new Response(JSON.stringify({ status: "success" }), { headers });
    }
  }

  return new Response("VIP Server Running...", { status: 404 });
});

// HTML UI CODE
function renderHTML() {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIP Server Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>body{background:#111827;color:white;}</style>
</head>
<body class="p-4 flex flex-col items-center min-h-screen">
    
    <!-- Login Form -->
    <div id="loginBox" class="w-full max-w-sm bg-gray-800 p-6 rounded-lg shadow-lg mt-10">
        <h2 class="text-xl font-bold mb-4 text-center text-cyan-400">Admin Login</h2>
        <input type="password" id="passInput" placeholder="Enter Admin Password" class="w-full p-2 mb-4 rounded bg-gray-700 border border-gray-600 focus:outline-none focus:border-cyan-500">
        <button onclick="login()" class="w-full bg-cyan-600 hover:bg-cyan-500 p-2 rounded font-bold">LOGIN</button>
    </div>

    <!-- Main Panel -->
    <div id="panelBox" class="w-full max-w-4xl hidden">
        <div class="flex justify-between items-center mb-6">
            <h1 class="text-2xl font-bold text-cyan-400">VIP MANAGER</h1>
            <button onclick="logout()" class="text-red-400 text-sm">Logout</button>
        </div>

        <!-- Create Form -->
        <div class="bg-gray-800 p-4 rounded-lg mb-6 flex flex-col md:flex-row gap-2">
            <input id="newUser" type="text" placeholder="Username" class="p-2 rounded bg-gray-700 flex-1">
            <input id="newPass" type="text" placeholder="Password" class="p-2 rounded bg-gray-700 flex-1">
            <input id="newDays" type="number" value="30" placeholder="Days" class="p-2 rounded bg-gray-700 w-24">
            <button onclick="createUser()" class="bg-green-600 hover:bg-green-500 px-6 py-2 rounded font-bold">Create</button>
        </div>

        <!-- User List -->
        <div class="bg-gray-800 rounded-lg overflow-hidden">
            <table class="w-full text-left text-sm">
                <thead class="bg-gray-900 text-gray-400">
                    <tr>
                        <th class="p-3">User</th>
                        <th class="p-3">Pass</th>
                        <th class="p-3">Expires</th>
                        <th class="p-3">Left</th>
                        <th class="p-3 text-right">Action</th>
                    </tr>
                </thead>
                <tbody id="userList"></tbody>
            </table>
        </div>
    </div>

    <script>
        let PASS = localStorage.getItem("adm_pass");
        if(PASS) showPanel();

        function login() {
            PASS = document.getElementById("passInput").value;
            localStorage.setItem("adm_pass", PASS);
            showPanel();
        }

        function logout() {
            localStorage.removeItem("adm_pass");
            location.reload();
        }

        function showPanel() {
            document.getElementById("loginBox").classList.add("hidden");
            document.getElementById("panelBox").classList.remove("hidden");
            loadUsers();
        }

        async function api(path, data) {
            data.adminPass = PASS;
            const res = await fetch(path, { method: "POST", body: JSON.stringify(data) });
            return await res.json();
        }

        async function loadUsers() {
            const res = await api("/api/list", {});
            if(res.status !== "success") return alert("Login Failed");
            
            const tbody = document.getElementById("userList");
            tbody.innerHTML = "";
            res.data.sort((a,b)=>a.expiry - b.expiry).forEach(u => {
                const days = Math.ceil((u.expiry - Date.now())/(86400000));
                const statusColor = days > 0 ? "text-green-400" : "text-red-500";
                tbody.innerHTML += \`
                    <tr class="border-b border-gray-700 hover:bg-gray-750">
                        <td class="p-3 font-bold">\${u.username}</td>
                        <td class="p-3 text-gray-400">\${u.password}</td>
                        <td class="p-3">\${new Date(u.expiry).toLocaleDateString()}</td>
                        <td class="p-3 \${statusColor}">\${days > 0 ? days + " Days" : "Expired"}</td>
                        <td class="p-3 text-right space-x-1">
                            <button onclick="extend('\${u.username}')" class="bg-blue-600 px-2 py-1 rounded text-xs">Renew</button>
                            <button onclick="del('\${u.username}')" class="bg-red-600 px-2 py-1 rounded text-xs">Del</button>
                        </td>
                    </tr>\`;
            });
        }

        async function createUser() {
            await api("/api/create", {
                username: document.getElementById("newUser").value,
                password: document.getElementById("newPass").value,
                days: document.getElementById("newDays").value
            });
            document.getElementById("newUser").value = "";
            loadUsers();
        }

        async function extend(user) {
            const days = prompt("Add Days:", "30");
            if(days) { await api("/api/extend", { username: user, days }); loadUsers(); }
        }

        async function del(user) {
            if(confirm("Delete " + user + "?")) { await api("/api/delete", { username: user }); loadUsers(); }
        }
    </script>
</body>
</html>
  `;
}
