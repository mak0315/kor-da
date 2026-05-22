import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { verifyAdmin } from '@/lib/admin-auth';

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const auth = await verifyAdmin(req);
  if (!auth.ok) return auth.response;

  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data: listing, error } = await supabase
    .from('listings')
    .select('featured')
    .eq('id', params.id)
    .single();

  if (error || !listing) {
    return NextResponse.json({ ok: false, error: 'Listing not found.' }, { status: 404 });
  }

  await supabase.from('listings').update({ featured: !listing.featured }).eq('id', params.id);

  return NextResponse.json({ ok: true, featured: !listing.featured });
}
