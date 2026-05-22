import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";

async function checkAdmin(req: Request) {
  const token = (req.headers.get("authorization") || "").replace("Bearer ", "").trim();
  if (!token) return false;
  try { const p: any = jwt.verify(token, process.env.JWT_SECRET!); if (p?.role === "admin") return true; } catch (_) {}
  const sb = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data: { user } } = await sb.auth.getUser(token);
  return user?.email === process.env.ADMIN_EMAIL;
}

export async function GET(req: Request) {
  if (!await checkAdmin(req)) return NextResponse.json({ ok: false, error: "Forbidden" }, { status: 403 });
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data, error } = await supabase.from("waitlist").select("*");
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true, waitlist: data || [] });
}
