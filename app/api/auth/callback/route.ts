import { createClient } from '@/lib/supabase/server';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');
  const next = searchParams.get('next') ?? '/';

  const redirectTo = (path: string) =>
    new Response(null, {
      status: 302,
      headers: { Location: new URL(path, request.url).toString() },
    });

  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return redirectTo(next);
    }
  }

  return redirectTo('/auth/auth-code-error');
}
