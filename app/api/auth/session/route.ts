import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export async function GET() {
  const supabase = createClient();
  const { data: { session }, error } = await supabase.auth.getSession();

  if (error || !session) {
    return NextResponse.json({ ok: false, user: null });
  }

  return NextResponse.json({ 
    ok: true, 
    user: { 
      id: session.user.id, 
      email: session.user.email 
    } 
  });
}
