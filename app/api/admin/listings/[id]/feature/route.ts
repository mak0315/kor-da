import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@korda.pk';

async function isAdmin(supabase: any) {
  const { data: { session } } = await supabase.auth.getSession();
  return session?.user?.email === ADMIN_EMAIL;
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const supabase = await createClient();
  if (!(await isAdmin(supabase))) {
    return NextResponse.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;

  const { data: l, error: fetchErr } = await supabase
    .from('listings')
    .select('featured')
    .eq('id', id)
    .single();

  if (fetchErr || !l) {
    return NextResponse.json({ ok: false, error: 'Listing not found.' }, { status: 404 });
  }

  const { error: updateErr } = await supabase
    .from('listings')
    .update({ featured: !l.featured })
    .eq('id', id);

  if (updateErr) {
    return NextResponse.json({ ok: false, error: updateErr.message }, { status: 500 });
  }

  return NextResponse.json({ ok: true, featured: !l.featured });
}
