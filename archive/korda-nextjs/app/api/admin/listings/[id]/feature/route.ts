import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { verifyAdmin } from "@/lib/admin-auth";

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const auth = await verifyAdmin(req);
  if (!auth.ok) return auth.response;
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data: l, error } = await supabase.from("listings").select("featured").eq("id", params.id).single();
  if (error || !l) return NextResponse.json({ ok: false, error: "Not found." }, { status: 404 });
  await supabase.from("listings").update({ featured: !l.featured }).eq("id", params.id);
  return NextResponse.json({ ok: true, featured: !l.featured });
}
