import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';
import { sanitizeInput } from '@/lib/sanitize';
import { validEmail } from '@/lib/validators';
import { sendEmail } from '@/lib/email';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const raw = sanitizeInput(body.email || '', 200);

    if (!raw || !validEmail(raw)) {
      return NextResponse.json({ ok: false, error: 'Valid email required.' }, { status: 400 });
    }

    const email = raw.toLowerCase().trim();
    const { error } = await supabase.from('waitlist').insert([{ email }]);

    if (error && error.code === '23505') {
      return NextResponse.json({ ok: true, message: "You're already on the list!" });
    }

    if (error) throw error;

    await sendEmail({
      to: process.env.NOTIFY_EMAIL || process.env.GMAIL_USER!,
      subject: `📬 Waitlist: ${email}`,
      html: `<p>New signup: <strong>${email}</strong></p>`
    });

    return NextResponse.json({ ok: true, message: "You're on the list! Check your inbox." });
  } catch (error: any) {
    return NextResponse.json({ ok: false, error: 'Internal server error.' }, { status: 500 });
  }
}
