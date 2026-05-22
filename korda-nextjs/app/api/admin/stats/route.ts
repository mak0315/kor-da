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
  const [{ count: a },{ count: l },{ count: b },{ count: w },{ data: bks }] = await Promise.all([
    supabase.from("applications").select("*",{count:"exact",head:true}).eq("status","pending"),
    supabase.from("listings").select("*",{count:"exact",head:true}).eq("status","approved"),
    supabase.from("bookings").select("*",{count:"exact",head:true}),
    supabase.from("waitlist").select("*",{count:"exact",head:true}),
    supabase.from("bookings").select("commission").eq("status","checked_in"),
  ]);
  return NextResponse.json({ ok:true, stats:{ applications:{pending:a||0}, listings:{approved:l||0}, bookings:{total:b||0}, waitlist:{count:w||0}, revenue:{total:(bks||[]).reduce((s:number,x:any)=>s+(x.commission||0),0)} }});
}
