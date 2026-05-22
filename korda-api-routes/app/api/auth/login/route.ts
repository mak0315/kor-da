import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

function san(s: string, max = 2000) {
  return String(s || '').trim().replace(/<[^>]*>/g, '').replace(/javascript:/gi, '').slice(0, max);
}

export async function POST(req: Request) {
  const body = await req.json();
  const email = san(body.email || '', 200);
  const password = body.password;

  if (!email || !password) {
    return NextResponse.json({ ok: false, error: 'Email and password required.' }, { status: 400 });
  }

  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    return NextResponse.json({ ok: false, error: error.message }, { status: 401 });
  }

  return NextResponse.json({ ok: true, token: data.session?.access_token, user: data.user });
}
