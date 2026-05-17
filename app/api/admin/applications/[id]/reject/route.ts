import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@korda.pk';

async function isAdmin(supabase: any) {
  const { data: { session } } = await supabase.auth.getSession();
  return session?.user?.email === ADMIN_EMAIL;
}

function sanitize(s: string, max: number) {
  return String(s || '').trim()
    .replace(/<[^>]*>/g, '')
    .slice(0, max);
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
  let reason = 'Does not meet requirements';
  try {
    const body = await request.json();
    if (body.reason) reason = sanitize(body.reason, 500);
  } catch (e) {
    // ignore json parse error
  }

  const { error } = await supabase
    .from('applications')
    .update({ status: 'rejected', rejectedAt: new Date().toISOString(), rejectionReason: reason })
    .eq('id', id);

  if (error) {
    return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  }

  return NextResponse.json({ ok: true, message: 'Application rejected.' });
}
