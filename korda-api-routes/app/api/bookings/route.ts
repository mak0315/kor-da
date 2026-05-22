import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { verifyUser } from '@/lib/admin-auth';
import crypto from 'crypto';

function san(s: string, max = 2000) {
  return String(s || '').trim().replace(/<[^>]*>/g, '').slice(0, max);
}

export async function POST(req: Request) {
  const auth = await verifyUser(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const { listingId, checkIn, checkOut, guests } = body;

  if (!listingId || !checkIn || !checkOut) {
    return NextResponse.json({ ok: false, error: 'listingId, checkIn and checkOut are required.' }, { status: 400 });
  }

  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data: listing } = await supabase
    .from('listings')
    .select('*')
    .eq('id', san(listingId, 50))
    .eq('status', 'approved')
    .single();

  if (!listing) {
    return NextResponse.json({ ok: false, error: 'Listing not available.' }, { status: 404 });
  }

  const nights = Math.ceil((new Date(checkOut).getTime() - new Date(checkIn).getTime()) / 86400000);
  const total = nights * listing.price;
  const commission = parseFloat(process.env.COMMISSION_RATE || '0.08');

  const booking = {
    id: `BKG-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    listingId: listing.id,
    guestId: auth.user.id,
    checkIn: san(checkIn, 12),
    checkOut: san(checkOut, 12),
    guests: Math.min(20, Math.max(1, parseInt(guests) || 1)),
    nights,
    totalAmount: total,
    commission: Math.round(total * commission),
    hostPayout: total - Math.round(total * commission),
    status: 'pending_payment',
  };

  const { error } = await supabase.from('bookings').insert([booking]);
  if (error) {
    return NextResponse.json({ ok: false, error: 'Failed to create booking.' }, { status: 500 });
  }

  return NextResponse.json({ ok: true, booking }, { status: 201 });
}
