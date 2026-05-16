import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@korda.pk';

async function isAdmin(supabase: any) {
  const { data: { session } } = await supabase.auth.getSession();
  return session?.user?.email === ADMIN_EMAIL;
}

export async function GET() {
  const supabase = createClient();
  if (!(await isAdmin(supabase))) {
    return NextResponse.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  }

  const [
    { count: appsPending },
    { count: listsApproved },
    { count: bksTotal },
    { count: waitTotal },
    { data: bks }
  ] = await Promise.all([
    supabase.from('applications').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
    supabase.from('listings').select('*', { count: 'exact', head: true }).eq('status', 'approved'),
    supabase.from('bookings').select('*', { count: 'exact', head: true }),
    supabase.from('waitlist').select('*', { count: 'exact', head: true }),
    supabase.from('bookings').select('commission').eq('status', 'checked_in')
  ]);

  return NextResponse.json({
    ok: true,
    stats: {
      applications: { pending: appsPending || 0 },
      listings: { approved: listsApproved || 0 },
      bookings: { total: bksTotal || 0 },
      waitlist: { count: waitTotal || 0 },
      revenue: { total: (bks || []).reduce((s: number, b: any) => s + (b.commission || 0), 0) },
    }
  });
}
