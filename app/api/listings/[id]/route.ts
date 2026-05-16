import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const { data, error } = await supabase
    .from('listings')
    .select('*')
    .eq('id', params.id)
    .eq('status', 'approved')
    .single();

  if (error || !data) {
    return NextResponse.json({ ok: false, error: 'Listing not found.' }, { status: 404 });
  }

  // Sanitize host info if needed (as in server.js)
  const safe = { 
    ...data, 
    host: { 
      name: data.host?.name, 
      cnicVerified: true 
    } 
  };

  return NextResponse.json({ ok: true, listing: safe });
}
