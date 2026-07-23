import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import nodemailer from 'nodemailer';

function san(s: string, max = 2000) {
  return String(s || '').trim().replace(/<[^>]*>/g, '').replace(/javascript:/gi, '').slice(0, max);
}

async function sendEmail(to: string, subject: string, html: string, replyTo?: string) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASS) return;
  const mailer = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASS },
  });
  try {
    await mailer.sendMail({ from: `"Kor Da" <${process.env.GMAIL_USER}>`, to, subject, html, replyTo });
  } catch (err: any) {
    console.error('[EMAIL ERROR]', err.message);
  }
}

export async function POST(req: Request) {
  const body = await req.json();
  const name = san(body.name || '', 100);
  const email = san(body.email || '', 200);
  const subject = san(body.subject || '', 200);
  const message = san(body.message || '', 3000);

  if (!name || !email || !message || message.length < 5) {
    return NextResponse.json({ ok: false, error: 'Name, email, and message required.' }, { status: 400 });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ ok: false, error: 'Invalid email.' }, { status: 400 });
  }

  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);
  const { error } = await supabase.from('contacts').insert([{ name, email, subject, message }]);

  if (error) {
    return NextResponse.json({ ok: false, error: 'Failed to send message.' }, { status: 500 });
  }

  const notify = process.env.NOTIFY_EMAIL;
  if (notify) await sendEmail(notify, `📩 Contact: ${name}`, `<p>${message}</p>`, email);

  return NextResponse.json({ ok: true, message: "Message sent! We'll reply within 2 hours." });
}
