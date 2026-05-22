import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";

export async function POST(req: Request) {
  const { email, password } = await req.json();
  const ADMIN_PASS = process.env.ADMIN_PASS;
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
  const JWT_SECRET = process.env.JWT_SECRET!;
  if (!email && password === ADMIN_PASS) {
    const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "12h" });
    return NextResponse.json({ ok: true, token });
  }
  if (!email) return NextResponse.json({ ok: false, error: "Email required." }, { status: 400 });
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 401 });
  if (data.user.email !== ADMIN_EMAIL) return NextResponse.json({ ok: false, error: "Access denied." }, { status: 403 });
  return NextResponse.json({ ok: true, token: data.session.access_token });
}
