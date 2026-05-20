import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';

export const dynamic = 'force-dynamic';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@korda.pk';
const ADMIN_PASS = process.env.ADMIN_PASS || '';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_for_jwt_signing';

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();

    // Legacy password-only login (backward compatibility)
    if (!email && password === ADMIN_PASS) {
      const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
      return NextResponse.json({ ok: true, token });
    }

    if (!email) {
      return NextResponse.json({ ok: false, error: 'Email required' }, { status: 400 });
    }

    const supabase = await createClient();
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });

    if (error) {
      return NextResponse.json({ ok: false, error: error.message }, { status: 401 });
    }

    if (data.user?.email === ADMIN_EMAIL) {
      return NextResponse.json({ ok: true, token: data.session.access_token });
    } else {
      return NextResponse.json({ ok: false, error: 'Access denied: Not an administrator' }, { status: 403 });
    }
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: 'Internal server error' }, { status: 500 });
  }
}
