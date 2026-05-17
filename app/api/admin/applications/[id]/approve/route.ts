import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import * as crypto from 'crypto';

export const dynamic = 'force-dynamic';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@korda.pk';

async function isAdmin(supabase: any) {
  const { data: { session } } = await supabase.auth.getSession();
  return session?.user?.email === ADMIN_EMAIL;
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const supabase = createClient();
  if (!(await isAdmin(supabase))) {
    return NextResponse.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;

  const { data: appl, error: fetchErr } = await supabase
    .from('applications')
    .select('*')
    .eq('id', id)
    .single();

  if (fetchErr || !appl) {
    return NextResponse.json({ ok: false, error: 'Application not found.' }, { status: 404 });
  }

  await supabase
    .from('applications')
    .update({ status: 'approved', approvedAt: new Date().toISOString() })
    .eq('id', id);

  const listingId = 'LST-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const listing = {
    id: listingId,
    city: appl.property?.city || 'Islamabad',
    type: appl.property?.type || 'Entire House',
    price: appl.property?.price || 15000,
    ...appl.property,
    host: appl.host,
    status: 'approved',
    featured: false
  };

  const { error: insertErr } = await supabase.from('listings').insert([listing]);
  if (insertErr) {
    return NextResponse.json({ ok: false, error: insertErr.message }, { status: 500 });
  }

  return NextResponse.json({ ok: true, listing, message: 'Listing approved and live.' });
}
