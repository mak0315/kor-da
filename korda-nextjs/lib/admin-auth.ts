import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";

export async function verifyAdmin(req: Request): Promise<{ ok: true; user: any } | { ok: false; response: Response }> {
  const token = (req.headers.get("authorization") || "").replace("Bearer ", "").trim();
  if (!token) return { ok: false, response: NextResponse.json({ ok: false, error: "Auth required" }, { status: 401 }) };
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret) {
    try {
      const p = jwt.verify(token, jwtSecret) as any;
      if (p?.role === "admin") return { ok: true, user: p };
    } catch (_) {}
  }
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (!error && user && user.email === process.env.ADMIN_EMAIL) return { ok: true, user };
  return { ok: false, response: NextResponse.json({ ok: false, error: "Admin access required" }, { status: 403 }) };
}

export async function verifyUser(req: Request): Promise<{ ok: true; user: any } | { ok: false; response: Response }> {
  const token = (req.headers.get("authorization") || "").replace("Bearer ", "").trim();
  if (!token) return { ok: false, response: NextResponse.json({ ok: false, error: "Auth required" }, { status: 401 }) };
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (!error && user) return { ok: true, user: { id: user.id, email: user.email } };
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret) {
    try {
      const p = jwt.verify(token, jwtSecret) as any;
      if (p) return { ok: true, user: p };
    } catch (_) {}
  }
  return { ok: false, response: NextResponse.json({ ok: false, error: "Invalid token" }, { status: 401 }) };
}
