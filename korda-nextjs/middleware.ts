import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname;
  
  // Protect admin routes with IP restriction
  if (path.startsWith('/admin')) {
    const allowedIps = (process.env.ADMIN_ALLOWED_IPS || '').split(',').map((ip: string) => ip.trim());
    const clientIp = request.ip || request.headers.get('x-forwarded-for') || '127.0.0.1';
    
    // If strict IPs are configured and the client IP is not in the list, block them.
    // (We also check that allowedIps isn't just an empty string)
    if (allowedIps.length > 0 && allowedIps[0] !== '' && !allowedIps.includes(clientIp)) {
      console.warn(`Blocked admin access attempt from unauthorized IP: ${clientIp}`);
      return new NextResponse('Unauthorized access', { status: 403 });
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
