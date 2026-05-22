import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { verifyAdmin } from "@/lib/admin-auth";
import crypto from "crypto";

export async function POST(req: Request, { params }: { params: { id: string } }) {
  const auth = await verifyAdmin(req);
  if (!auth.ok) return auth.response;
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data: appl, error } = await supabase.from("applications").select("*").eq("id", params.id).single();
  if (error || !appl) return NextResponse.json({ ok: false, error: "Not found." }, { status: 404 });
  await supabase.from("applications").update({ status: "approved", approvedAt: new Date().toISOString() }).eq("id", params.id);
  const listing = { id: "LST-" + Date.now() + "-" + crypto.randomBytes(4).toString("hex").toUpperCase(), ...appl.property, host: appl.host, status: "approved", featured: false };
  await supabase.from("listings").insert([listing]);
  return NextResponse.json({ ok: true, listing, message: "Listing approved and live." });
}
