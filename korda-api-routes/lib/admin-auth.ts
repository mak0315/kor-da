import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import { NextResponse } from 'next/server';

function getSupabase() {
  return createClient(
    process.env.SUPABASE_URL!,
    process.env.SUPABASE_KEY!
  );
}

export async function verifyAdmin(req: Request): Promise<{ ok: true; user: any } | { ok: false; response: Response }> {
  const authHeader = req.headers.get('authorization') || '';
  const token = authHeader.replace('Bearer ', '').trim();

  if (!token) {
    return { ok: false, response: NextResponse.json({ ok: false, error: 'Authentication required' }, { status: 401 }) };
  }

  const jwtSecret = process.env.JWT_SECRET;
  const adminEmail = process.env.ADMIN_EMAIL;

  // Try legacy JWT first (role=admin)
  if (jwtSecret) {
    try {
      const payload = jwt.verify(token, jwtSecret) as any;
      if (payload?.role === 'admin') {
        return { ok: true, user: payload };
      }
    } catch (_) {
      // not a valid JWT, try Supabase
    }
  }

  // Try Supabase token
  const supabase = getSupabase();
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (!error && user && user.email === adminEmail) {
    return { ok: true, user };
  }

  return { ok: false, response: NextResponse.json({ ok: false, error: 'Admin access required' }, { status: 403 }) };
}

export async function verifyUser(req: Request): Promise<{ ok: true; user: any } | { ok: false; response: Response }> {
  const authHeader = req.headers.get('authorization') || '';
  const token = authHeader.replace('Bearer ', '').trim();

  if (!token) {
    return { ok: false, response: NextResponse.json({ ok: false, error: 'Authentication required' }, { status: 401 }) };
  }

  const supabase = getSupabase();
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (!error && user) {
    return { ok: true, user: { id: user.id, email: user.email, role: 'user' } };
  }

  // Fallback: legacy JWT
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret) {
    try {
      const payload = jwt.verify(token, jwtSecret) as any;
      if (payload) return { ok: true, user: payload };
    } catch (_) {}
  }

  return { ok: false, response: NextResponse.json({ ok: false, error: 'Token invalid or expired' }, { status: 401 }) };
}
