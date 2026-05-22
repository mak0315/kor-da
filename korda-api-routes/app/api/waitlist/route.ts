import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import nodemailer from 'nodemailer';

async function sendEmail(to: string, subject: string, html: string) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASS) return;
  const mailer = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASS },
  });
  try {
    await mailer.sendMail({ from: `"Kor Da" <${process.env.GMAIL_USER}>`, to, subject, html });
  } catch (err: any) {
    console.error('[EMAIL ERROR]', err.message);
  }
}

export async function POST(req: Request) {
  const body = await req.json();
  const raw = String(body.email || '').trim().toLowerCase();

  if (!raw || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw)) {
    return NextResponse.json({ ok: false, error: 'Valid email required.' }, { status: 400 });
  }

  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { error } = await supabase.from('waitlist').insert([{ email: raw }]);

  if (error) {
    if ((error as any).code === '23505') {
      return NextResponse.json({ ok: true, message: "You're already on the list!" });
    }
    return NextResponse.json({ ok: false, error: 'Failed to join waitlist.' }, { status: 500 });
  }

  const notify = process.env.NOTIFY_EMAIL;
  if (notify) await sendEmail(notify, `📬 Waitlist: ${raw}`, `<p>New signup: <strong>${raw}</strong></p>`);

  return NextResponse.json({ ok: true, message: "You're on the list! Check your inbox." });
}
