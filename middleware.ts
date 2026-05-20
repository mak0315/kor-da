import { createServerClient, type CookieOptions } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  let response = NextResponse.next();

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        get(name: string) {
          return request.cookies.get(name)?.value;
        },
        set(name: string, value: string, options: CookieOptions) {
          response.cookies.set({
            name,
            value,
            ...options,
          });
        },
        remove(name: string, options: CookieOptions) {
          response = NextResponse.next();
          response.cookies.set({
            name,
            value: '',
            ...options,
          });
        },
      },
    }
  );

  const { data: { session } } = await supabase.auth.getSession();

  const path = request.nextUrl.pathname;
  
  // IP restriction for admin routes
  if (path.startsWith('/admin')) {
    const allowedIps = (process.env.ADMIN_ALLOWED_IPS || '').split(',').map((ip: string) => ip.trim());
    const clientIp = request.ip || request.headers.get('x-forwarded-for') || '127.0.0.1';
    
    if (allowedIps.length > 0 && allowedIps[0] !== '' && !allowedIps.includes(clientIp)) {
      console.warn(`Blocked admin access attempt from unauthorized IP: ${clientIp}`);
      return new NextResponse('Unauthorized access', { status: 403 });
    }

    // Also check if user is admin (requires session)
    if (!session) {
      return (NextResponse as any).redirect(new URL('/login?next=' + path, request.url));
    }
  }

  return response;
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
