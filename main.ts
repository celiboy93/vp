const kv = await Deno.openKv();
const ADMIN_PASSWORD = "admin";
Deno.serve(async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;
  let params = {};
  try {
    const text = await req.text();
    if (text.startsWith("{")) params = JSON.parse(text);
    else params = Object.fromEntries(new URLSearchParams(text));
  } catch (e) {}
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  };
  if (path.includes("login")) {
    const { username, password, device_id } = params;
    const entry = await kv.get(["users", username]);
    if (!entry.value) return new Response(JSON.stringify({ status: "fail", message: "User not found" }), { headers });
    const account = entry.value;
    if (account.password !== password) return new Response(JSON.stringify({ status: "fail", message: "Wrong Password" }), { headers });
    if (Date.now() > account.expiry) return new Response(JSON.stringify({ status: "expired", message: "Expired" }), { headers });
    const userDevId = device_id || "unknown";
    if (account.device_id && account.device_id !== userDevId) {
       return new Response(JSON.stringify({ status: "fail", message: "Device Mismatch" }), { headers });
    }
    const remainingDays = Math.ceil((account.expiry - Date.now()) / (24 * 60 * 60 * 1000));
    const expiryString = remainingDays.toString(); 
    if (account.device_id) {
        return new Response(JSON.stringify({
            "status": "re_login",
            "user": username,
            "expired_date": account.expiry.toString(), 
            "device_id": account.device_id,
            "message": "Welcome Back",
            "access": "true"
        }), { headers });
    }
    return new Response(JSON.stringify({
        "status": "login",
        "user": username,
        "expired_date": expiryString, 
        "message": "Login Success",
        "access": "true"
    }), { headers });
  }
  if (path.includes("reupload") || path.includes("edit")) {
     const { username, device_id, expired_date } = params;
     if (username) {
         const entry = await kv.get(["users", username]);
         if (entry.value) {
             const acc = entry.value;
             if (!acc.device_id && device_id) {
                 acc.device_id = device_id;
                 await kv.set(["users", username], acc);
             }
         }
     }
     return new Response(JSON.stringify({"status": "success"}), { headers });
  }
  if (path.includes("checkUsername") || path.includes("exist")) {
     const { username } = params;
     const entry = await kv.get(["users", username]);
     if (entry.value && entry.value.expiry > Date.now()) {
         return new Response(JSON.stringify({"status": "success"}), { headers });
     }
     return new Response(JSON.stringify({"status": "fail"}), { headers });
  }
  if (path.includes("delete")) {
     const username = params.usernameToDelete || params.username;
     if(username) await kv.delete(["users", username]);
     return new Response(JSON.stringify({"status": "success"}), { headers });
  }
  if (req.method === "GET" && path === "/") return new Response(renderHTML(), { headers: { "content-type": "text/html" } });
  if (path.startsWith("/api/")) {
      if (params.adminPass !== ADMIN_PASSWORD) return new Response(JSON.stringify({status:"fail"}),{headers});
      if (path === "/api/list") {
          const users = [];
          for await (const entry of kv.list({ prefix: ["users"] })) users.push(entry.value);
          return new Response(JSON.stringify({status:"success", data:users}),{headers});
      }
      if (path === "/api/create") {
          const exp = Date.now() + (parseInt(params.days) * 86400000);
          await kv.set(["users", params.username], { 
              username: params.username, 
              password: params.password, 
              expiry: exp, 
              device_id: null 
          });
          return new Response(JSON.stringify({status:"success"}),{headers});
      }
      if (path === "/api/resetid") {
          const e = await kv.get(["users", params.username]);
          if(e.value) { e.value.device_id = null; await kv.set(["users", params.username], e.value); }
          return new Response(JSON.stringify({status:"success"}),{headers});
      }
      if (path === "/api/extend") {
          const e = await kv.get(["users", params.username]);
          if(e.value) { 
            e.value.expiry = Math.max(Date.now(), e.value.expiry) + (parseInt(params.days)*86400000); 
            await kv.set(["users", params.username], e.value); 
          }
          return new Response(JSON.stringify({status:"success"}),{headers});
      }
      if (path === "/api/delete") {
          await kv.delete(["users", params.username]);
          return new Response(JSON.stringify({status:"success"}),{headers});
      }
  }
  return new Response("VIP Server", { status: 200 });
});
function renderHTML() {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>VIP Manager</title><script src="https://cdn.tailwindcss.com"></script><style>body{background:#111827;color:#fff}</style></head><body class="flex justify-center p-5"><div id="auth" class="w-full max-w-sm mt-10 p-5 bg-gray-800 rounded"><h2 class="text-xl mb-3 text-cyan-400 font-bold">Admin Login</h2><input id="pw" type="password" class="w-full p-2 bg-gray-700 rounded mb-3" placeholder="Password"><button onclick="login()" class="w-full bg-cyan-600 p-2 rounded">LOGIN</button></div><div id="app" class="w-full max-w-4xl hidden"><div class="flex justify-between mb-5"><h1 class="text-2xl font-bold text-cyan-400">VIP MANAGER</h1><button onclick="logout()" class="text-red-400">Logout</button></div><div class="flex gap-2 mb-5"><input id="u" placeholder="User" class="p-2 bg-gray-800 rounded flex-1"><input id="p" placeholder="Pass" class="p-2 bg-gray-800 rounded flex-1"><input id="d" type="number" value="30" class="p-2 bg-gray-800 rounded w-16"><button onclick="api('/api/create',{username:getId('u'),password:getId('p'),days:getId('d')})" class="bg-green-600 p-2 rounded">Create</button></div><table class="w-full text-sm bg-gray-800 rounded overflow-hidden"><thead class="bg-gray-900 text-left"><tr><th class="p-3">User</th><th class="p-3">Pass</th><th class="p-3">Expires</th><th class="p-3">Device</th><th class="p-3 text-right">Action</th></tr></thead><tbody id="list"></tbody></table></div><script>let T=localStorage.getItem("t");const getId=i=>document.getElementById(i).value;if(T)show();function login(){T=getId("pw");localStorage.setItem("t",T);show()}function logout(){localStorage.removeItem("t");location.reload()}function show(){document.getElementById("auth").classList.add("hidden");document.getElementById("app").classList.remove("hidden");load()}async function api(e,d={}){d.adminPass=T;await fetch(e,{method:"POST",body:JSON.stringify(d)});if(e.includes("list"))return;load()}async function load(){const r=await fetch("/api/list",{method:"POST",body:JSON.stringify({adminPass:T})});const j=await r.json();if(j.status!="success")return;const l=document.getElementById("list");l.innerHTML="";j.data.sort((a,b)=>a.expiry-b.expiry).forEach(u=>{const d=Math.ceil((u.expiry-Date.now())/86400000);const dev=u.device_id?"<span class='text-cyan-300'>Locked</span>":"<span class='text-gray-500'>--</span>";l.innerHTML+=\`<tr class="border-b border-gray-700"><td class="p-3 font-bold">\${u.username}</td><td class="p-3 opacity-75">\${u.password}</td><td class="p-3">\${new Date(u.expiry).toLocaleDateString()} (\${d}d)</td><td class="p-3">\${dev}</td><td class="p-3 text-right"><button onclick="api('/api/resetid',{username:'\${u.username}'})" class="text-yellow-400 mr-2">Reset</button><button onclick="api('/api/extend',{username:'\${u.username}',days:30})" class="text-blue-400 mr-2">Renew</button><button onclick="api('/api/delete',{username:'\${u.username}'})" class="text-red-400">Del</button></td></tr>\`})}</script></body></html>`;
}
