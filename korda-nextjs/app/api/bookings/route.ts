import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

export async function POST(req: Request) {
  const token = (req.headers.get("authorization") || "").replace("Bearer ", "").trim();
  if (!token) return NextResponse.json({ ok: false, error: "Authentication required." }, { status: 401 });
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data: { user }, error: authErr } = await supabase.auth.getUser(token);
  if (authErr || !user) return NextResponse.json({ ok: false, error: "Invalid token." }, { status: 401 });
  const { listingId, checkIn, checkOut, guests } = await req.json();
  if (!listingId || !checkIn || !checkOut) return NextResponse.json({ ok: false, error: "Missing fields." }, { status: 400 });
  const { data: listing } = await supabase.from("listings").select("*").eq("id", listingId).eq("status", "approved").single();
  if (!listing) return NextResponse.json({ ok: false, error: "Listing not available." }, { status: 404 });
  const nights = Math.ceil((new Date(checkOut).getTime() - new Date(checkIn).getTime()) / 86400000);
  const total = nights * listing.price;
  const commission = parseFloat(process.env.COMMISSION_RATE || "0.08");
  const booking = { id: "BKG-" + Date.now() + "-" + crypto.randomBytes(4).toString("hex").toUpperCase(), listingId: listing.id, guestId: user.id, checkIn, checkOut, guests: Math.min(20, Math.max(1, parseInt(guests) || 1)), nights, totalAmount: total, commission: Math.round(total * commission), hostPayout: total - Math.round(total * commission), status: "pending_payment" };
  const { error } = await supabase.from("bookings").insert([booking]);
  if (error) return NextResponse.json({ ok: false, error: "Failed to create booking." }, { status: 500 });
  return NextResponse.json({ ok: true, booking }, { status: 201 });
}
