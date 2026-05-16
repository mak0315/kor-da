import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
import * as crypto from 'crypto';

const COMMISSION_RATE = 0.08;

export async function POST(request: Request) {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();

  if (!session) {
    return NextResponse.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  }

  const body = await request.json();
  const { listingId, checkIn, checkOut, guests } = body;

  if (!listingId || !checkIn || !checkOut) {
    return NextResponse.json({ ok: false, error: 'All fields are required.' }, { status: 400 });
  }

  // Fetch listing details to calculate price
  const { data: listing, error: lError } = await supabase
    .from('listings')
    .select('*')
    .eq('id', listingId)
    .eq('status', 'approved')
    .single();

  if (lError || !listing) {
    return NextResponse.json({ ok: false, error: 'Listing not found or not available.' }, { status: 404 });
  }

  const checkInDate = new Date(checkIn);
  const checkOutDate = new Date(checkOut);
  const diffTime = Math.abs(checkOutDate.getTime() - checkInDate.getTime());
  const nights = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

  if (nights <= 0) {
    return NextResponse.json({ ok: false, error: 'Invalid dates.' }, { status: 400 });
  }

  const totalAmount = nights * listing.price;
  const commission = Math.round(totalAmount * COMMISSION_RATE);
  const hostPayout = totalAmount - commission;

  const bookingId = `BKG-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

  const { error: bError } = await supabase.from('bookings').insert([{
    id: bookingId,
    listingId: listing.id,
    guestId: session.user.id,
    checkIn,
    checkOut,
    guests: Math.min(20, Math.max(1, parseInt(guests) || 1)),
    nights,
    totalAmount,
    commission,
    hostPayout,
    status: 'pending_payment'
  }]);

  if (bError) {
    return NextResponse.json({ ok: false, error: 'Failed to create booking.' }, { status: 500 });
  }

  return NextResponse.json({ ok: true, booking: { id: bookingId, totalAmount } }, { status: 201 });
}

export async function GET(request: Request) {
  const supabase = createClient();
  const { data: { session } } = await supabase.auth.getSession();

  if (!session) {
    return NextResponse.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  }

  const { data, error } = await supabase
    .from('bookings')
    .select('*, listings(*)')
    .eq('guestId', session.user.id);

  if (error) {
    return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  }

  return NextResponse.json({ ok: true, bookings: data });
}
