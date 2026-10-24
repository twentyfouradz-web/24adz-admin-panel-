const encoder = new TextEncoder();

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

async function verifyAdmin(request, env) {
  if (!env.ADMIN_SESSION_SECRET) return false;

  const token = request.headers.get("X-Admin-Token");
  const signature = request.headers.get("X-Admin-Signature");

  if (!token || !signature) return false;

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(env.ADMIN_SESSION_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const binary = atob(signature);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));

    return await crypto.subtle.verify(
      "HMAC",
      key,
      bytes,
      encoder.encode(token)
    );
  } catch {
    return false;
  }
}

export async function onRequestPost({ request, env }) {
  try {
    if (!(await verifyAdmin(request, env))) {
      return json({
        success: false,
        message: "Admin authentication failed"
      }, 401);
    }

    if (!env.DB) {
      return json({
        success: false,
        message: "D1 database binding DB is missing"
      }, 500);
    }

    const body = await request.json();

    const title = String(body.title || "").trim();
    const description = String(body.description || "").trim();
    const category = String(body.category || "").trim();
    const model = String(body.model || "").trim();
    const location = String(body.location || "").trim();
    const phone = String(body.phone || "").trim();
    const whatsapp = String(body.whatsapp || "").trim();
    const imageKey = String(body.image_key || "").trim();

    const allowedCategories = [
      "Cars",
      "Bikes",
      "Mobiles",
      "Houses",
      "Jobs",
      "House Movers"
    ];

    if (!title || !description || !location || !category) {
      return json({
        success: false,
        message: "Title, description, category and location are required"
      }, 400);
    }

    if (!allowedCategories.includes(category)) {
      return json({
        success: false,
        message: "Invalid category"
      }, 400);
    }

    const result = await env.DB.prepare(`
      INSERT INTO ads
      (title, description, category, model, location, phone, whatsapp,
       image_key, status, published, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'published', 1,
              CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(
      title,
      description,
      category,
      model,
      location,
      phone,
      whatsapp,
      imageKey
    ).run();

    return json({
      success: true,
      message: "Advertisement saved",
      id: result.meta?.last_row_id ?? null
    }, 201);

  } catch (error) {
    return json({
      success: false,
      message: "Could not save advertisement. Check the ads table columns."
    }, 500);
  }
}
