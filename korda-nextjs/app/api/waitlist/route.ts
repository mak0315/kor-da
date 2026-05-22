import { NextResponse } from 'next/server';
import { sanitizeInput } from '@/lib/sanitize';

// Lightweight route using Edge Runtime for maximum performance
export const runtime = 'edge';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    
    // Applying our input sanitization to strip XSS vectors
    const email = sanitizeInput(body.email);
    
    if (!email) {
      return NextResponse.json({ error: 'Email is required' }, { status: 400 });
    }

    // TODO: Supabase integration for waitlist
    
    return NextResponse.json({ success: true, message: 'Added to waitlist' });
  } catch (error) {
    // Proper error handling/throwing instead of process.exit()
    console.error('Waitlist route error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
