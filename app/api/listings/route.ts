import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const city = searchParams.get('city');
  const category = searchParams.get('category');
  const minPrice = searchParams.get('minPrice');
  const maxPrice = searchParams.get('maxPrice');
  const page = parseInt(searchParams.get('page') || '1');
  const limit = parseInt(searchParams.get('limit') || '12');

  let query = supabase
    .from('listings')
    .select('*', { count: 'exact' })
    .eq('status', 'approved');

  if (city) query = query.ilike('city', `%${city}%`);
  if (category && category !== 'all') query = query.eq('category', category);
  if (minPrice) query = query.gte('price', Number(minPrice));
  if (maxPrice) query = query.lte('price', Number(maxPrice));

  const p = Math.max(1, page);
  const lim = Math.min(50, Math.max(1, limit));
  
  const { data, count, error } = await query.range((p - 1) * lim, p * lim - 1);

  if (error) {
    return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  }

  return NextResponse.json({ 
    ok: true, 
    listings: data || [], 
    total: count || 0, 
    page: p, 
    pages: Math.ceil((count || 0) / lim) 
  });
}
