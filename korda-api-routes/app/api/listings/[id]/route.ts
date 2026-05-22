import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { data, error } = await supabase
    .from('listings')
    .select('*')
    .eq('id', params.id)
    .eq('status', 'approved')
    .single();

  if (error || !data) {
    return NextResponse.json({ ok: false, error: 'Listing not found.' }, { status: 404 });
  }

  return NextResponse.json({ ok: true, listing: data });
}
