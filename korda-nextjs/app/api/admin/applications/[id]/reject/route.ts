import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { verifyAdmin } from "@/lib/admin-auth";

export async function POST(req: Request, { params }: { params: { id: string } }) {
  const auth = await verifyAdmin(req);
  if (!auth.ok) return auth.response;
  const { reason = "Does not meet requirements" } = await req.json();
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  await supabase.from("applications").update({ status: "rejected", rejectedAt: new Date().toISOString(), rejectionReason: reason }).eq("id", params.id);
  return NextResponse.json({ ok: true, message: "Application rejected." });
}
