import { NextResponse } from 'next/server';

// Lightweight route using Edge Runtime for maximum performance
export const runtime = 'edge';

export async function GET() {
  return NextResponse.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString() 
  });
}
