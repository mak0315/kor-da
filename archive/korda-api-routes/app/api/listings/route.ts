import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const city = searchParams.get('city') || '';
  const category = searchParams.get('category') || '';
  const minPrice = parseInt(searchParams.get('minPrice') || '0');
  const maxPrice = parseInt(searchParams.get('maxPrice') || '0');
  const page = Math.max(1, parseInt(searchParams.get('page') || '1'));
  const limit = Math.min(50, Math.max(1, parseInt(searchParams.get('limit') || '12')));

  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  let query = supabase.from('listings').select('*', { count: 'exact' }).eq('status', 'approved');

  if (city) query = query.ilike('city', `%${city}%`);
  if (category && category !== 'all') query = query.eq('category', category);
  if (!isNaN(minPrice) && minPrice > 0) query = query.gte('price', minPrice);
  if (!isNaN(maxPrice) && maxPrice > 0) query = query.lte('price', maxPrice);

  const from = (page - 1) * limit;
  const { data, count, error } = await query.range(from, from + limit - 1);

  if (error) {
    return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  }

  return NextResponse.json({
    ok: true,
    listings: data ?? [],
    total: count || 0,
    page,
    pages: Math.ceil((count || 0) / limit),
  });
}
