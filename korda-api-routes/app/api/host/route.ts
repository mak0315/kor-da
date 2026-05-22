import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

function san(s: string, max = 2000) {
  return String(s || '').trim().replace(/<[^>]*>/g, '').replace(/javascript:/gi, '').slice(0, max);
}
function validCNIC(c: string) {
  const s = String(c || '').replace(/\s/g, '');
  return /^\d{5}-\d{7}-\d$/.test(s) ? s : null;
}
function validPrice(n: string) {
  const v = parseInt(n);
  return !isNaN(v) && v >= 100 && v <= 10000000 ? v : null;
}

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
  const form = await req.formData();

  const name = san(form.get('name')?.toString() ?? '', 100);
  const phone = san(form.get('phone')?.toString() ?? '', 20);
  const cnic = form.get('cnic')?.toString() ?? '';
  const city = san(form.get('city')?.toString() ?? '', 100);
  const address = san(form.get('address')?.toString() ?? '', 500);
  const type = san(form.get('type')?.toString() ?? '', 100);
  const beds = san(form.get('beds')?.toString() ?? '', 50);
  const priceRaw = form.get('price')?.toString() ?? '';
  const maxGuests = parseInt(form.get('maxGuests')?.toString() ?? '4') || 4;
  const description = san(form.get('description')?.toString() ?? '', 2000);
  const category = san(form.get('category')?.toString() ?? '', 100);
  const email = san(form.get('email')?.toString() ?? '', 200);

  if (!name || !phone || !cnic || !city || !address) {
    return NextResponse.json({ ok: false, error: 'Please fill all required fields.' }, { status: 400 });
  }
  const cnicClean = validCNIC(cnic);
  if (!cnicClean) {
    return NextResponse.json({ ok: false, error: 'CNIC format: 00000-0000000-0' }, { status: 400 });
  }
  const priceVal = validPrice(priceRaw);
  if (!priceVal) {
    return NextResponse.json({ ok: false, error: 'Price must be PKR 100 to 10,000,000.' }, { status: 400 });
  }

  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_KEY!);

  // Upload photos to Supabase Storage
  const photos: string[] = [];
  const files = form.getAll('photos');
  for (const file of files) {
    if (file instanceof File) {
      const ext = file.name.split('.').pop()?.toLowerCase() ?? 'jpg';
      const fileName = `${Date.now()}-${crypto.randomBytes(10).toString('hex')}.${ext}`;
      const { data, error } = await supabase.storage
        .from('uploads')
        .upload(fileName, Buffer.from(await file.arrayBuffer()), { contentType: file.type });
      if (!error && data?.path) {
        const { data: urlData } = supabase.storage.from('uploads').getPublicUrl(data.path);
        photos.push(urlData.publicUrl);
      }
    }
  }

  const appId = `APP-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const amenitiesRaw = form.getAll('amenities');
  const amenities = amenitiesRaw.map((a) => san(a.toString(), 50));

  const appData = {
    id: appId,
    status: 'pending',
    host: { name, phone, cnic: cnicClean, email },
    property: { city, type, beds, price: priceVal, maxGuests, address, description, category, photos, amenities },
  };

  const { error } = await supabase.from('applications').insert([appData]);
  if (error) {
    return NextResponse.json({ ok: false, error: 'Database error. Please try again.' }, { status: 500 });
  }

  const notify = process.env.NOTIFY_EMAIL;
  if (notify) await sendEmail(notify, `🏡 HOST APPLICATION [${appId}]`, `<p>New host application submitted.</p>`);

  return NextResponse.json({ ok: true, message: "Application received! We'll WhatsApp you.", id: appId });
}
