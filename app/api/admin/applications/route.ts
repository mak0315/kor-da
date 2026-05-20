import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@korda.pk';

async function isAdmin(supabase: any) {
  const { data: { session } } = await supabase.auth.getSession();
  return session?.user?.email === ADMIN_EMAIL;
}

export async function GET() {
  const supabase = await createClient();
  if (!(await isAdmin(supabase))) {
    return NextResponse.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  }

  const { data, error } = await supabase.from('applications').select('*');
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true, applications: data || [] });
}
