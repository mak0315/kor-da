import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { verifyAdmin } from "@/lib/admin-auth";

export async function GET(req: Request) {
  const auth = await verifyAdmin(req);
  if (!auth.ok) return auth.response;
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const [{ count: a },{ count: l },{ count: b },{ count: w },{ data: bks }] = await Promise.all([
    supabase.from("applications").select("*",{count:"exact",head:true}).eq("status","pending"),
    supabase.from("listings").select("*",{count:"exact",head:true}).eq("status","approved"),
    supabase.from("bookings").select("*",{count:"exact",head:true}),
    supabase.from("waitlist").select("*",{count:"exact",head:true}),
    supabase.from("bookings").select("commission").eq("status","checked_in"),
  ]);
  return NextResponse.json({ ok:true, stats:{ applications:{pending:a||0}, listings:{approved:l||0}, bookings:{total:b||0}, waitlist:{count:w||0}, revenue:{total:(bks||[]).reduce((s:number,b:any)=>s+(b.commission||0),0)} }});
}
