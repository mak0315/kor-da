import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { verifyAdmin } from '@/lib/admin-auth';

function san(s: string, max = 2000) {
  return String(s || '').trim().replace(/<[^>]*>/g, '').slice(0, max);
}

export async function POST(req: Request, { params }: { params: { id: string } }) {
  const auth = await verifyAdmin(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const reason = san(body.reason || 'Does not meet requirements', 500);

  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  await supabase
    .from('applications')
    .update({ status: 'rejected', rejectedAt: new Date().toISOString(), rejectionReason: reason })
    .eq('id', params.id);

  return NextResponse.json({ ok: true, message: 'Application rejected.' });
}
