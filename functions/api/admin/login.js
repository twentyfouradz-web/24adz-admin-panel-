export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();

    if (!env.ADMIN_PASSWORD || !env.ADMIN_SESSION_SECRET) {
      return Response.json(
        { success: false, message: "Admin secrets are not configured" },
        { status: 500 }
      );
    }

    if (body.password !== env.ADMIN_PASSWORD) {
      return Response.json(
        { success: false, message: "Invalid password" },
        { status: 401 }
      );
    }

    const token = crypto.randomUUID();
    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(env.ADMIN_SESSION_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(token)
    );

    const signed = btoa(
      String.fromCharCode(...new Uint8Array(signature))
    );

    return Response.json(
      {
        success: true,
        message: "Password accepted",
        token,
        signature: signed
      },
      {
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  } catch {
    return Response.json(
      { success: false, message: "Invalid request" },
      { status: 400 }
    );
  }
}
