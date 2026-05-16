import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';
import { sanitizeInput } from '@/lib/sanitize';
import { validEmail } from '@/lib/validators';
import { sendEmail } from '@/lib/email';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const name = sanitizeInput(body.name || '', 100);
    const email = sanitizeInput(body.email || '', 200);
    const subject = sanitizeInput(body.subject || '', 200);
    const message = sanitizeInput(body.message || '', 3000);

    if (!name || !email || !message || message.length < 5) {
      return NextResponse.json({ ok: false, error: 'Name, email, and message required.' }, { status: 400 });
    }

    if (!validEmail(email)) {
      return NextResponse.json({ ok: false, error: 'Invalid email.' }, { status: 400 });
    }

    const { error } = await supabase.from('contacts').insert([{ name, email, subject, message }]);

    if (error) throw error;

    await sendEmail({
      to: process.env.NOTIFY_EMAIL || process.env.GMAIL_USER!,
      subject: `📩 Contact: ${name}`,
      html: `<p>${message}</p>`,
      replyTo: email
    });

    return NextResponse.json({ ok: true, message: "Message sent! We'll reply within 2 hours." });
  } catch (error: any) {
    return NextResponse.json({ ok: false, error: 'Failed to send message.' }, { status: 500 });
  }
}
