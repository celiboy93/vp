Deno.serve(async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;
  
  // Headers (Error မတက်အောင်)
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  };

  // 1. LOGIN (အရေးအကြီးဆုံး)
  if (path.includes("login")) {
    const responseData = {
      "status": "login",       // MainActivity မှာ ဒီစာသားကို စစ်ထားလို့ မရှိမဖြစ်ပါ
      "user": "VIP User",      // App ထဲပြမယ့်နာမည်
      "expired_date": "30",    // ရက် ၃၀ (App က ဒီဂဏန်းကို ယူပြီး ရက်ပေါင်းထည့်ပါတယ်)
      "message": "Login Success",
      "access": "true"
    };
    return new Response(JSON.stringify(responseData), { headers });
  }

  // 2. USER EXIST (App ဖွင့်ဖွင့်ချင်း စစ်တတ်တယ်)
  if (path.includes("exist")) {
    const responseData = {
        "status": "success", 
        "message": "User active"
    };
    return new Response(JSON.stringify(responseData), { headers });
  }

  // 3. REUPLOAD / EDIT (Login ဝင်ပြီးရင် Date ကို Server ပေါ်ပြန်တင်တဲ့နေရာ)
  // App က Error မတက်အောင် Success လို့ပဲ ပြန်ပြောလိုက်မယ်
  if (path.includes("reupload") || path.includes("edit")) {
     return new Response(JSON.stringify({"status": "success"}), { headers });
  }

  // 4. DELETE (သက်တမ်းကုန်ရင် ဖျက်တဲ့နေရာ)
  if (path.includes("delete")) {
     return new Response(JSON.stringify({"status": "success"}), { headers });
  }

  // ဘာမှမဟုတ်ရင် 404
  return new Response("Not Found", { status: 404 });
});
