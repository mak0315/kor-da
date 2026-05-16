import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';
import { sanitizeInput } from '@/lib/sanitize';
import { validCNIC, validPrice } from '@/lib/validators';
import { sendEmail } from '@/lib/email';
import crypto from 'crypto';

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    
    // Extract fields
    const name = sanitizeInput(formData.get('name') as string, 100);
    const phone = sanitizeInput(formData.get('phone') as string, 20);
    const cnic = formData.get('cnic') as string;
    const city = sanitizeInput(formData.get('city') as string, 100);
    const type = sanitizeInput(formData.get('type') as string, 100);
    const beds = sanitizeInput(formData.get('beds') as string, 50);
    const price = formData.get('price') as string;
    const address = sanitizeInput(formData.get('address') as string, 500);
    const description = sanitizeInput(formData.get('description') as string, 2000);
    const category = sanitizeInput(formData.get('category') as string, 100);
    const email = sanitizeInput(formData.get('email') as string, 200);
    const maxGuests = parseInt(formData.get('maxGuests') as string) || 4;
    const amenitiesRaw = formData.get('amenities');
    const photos = formData.getAll('photos') as File[];

    // Validation
    if (!name || !phone || !cnic || !city || !address) {
      return NextResponse.json({ ok: false, error: 'Please fill all required fields.' }, { status: 400 });
    }

    const cnicClean = validCNIC(cnic);
    if (!cnicClean) {
      return NextResponse.json({ ok: false, error: 'CNIC format: 00000-0000000-0' }, { status: 400 });
    }

    const priceVal = validPrice(price);
    if (!priceVal) {
      return NextResponse.json({ ok: false, error: 'Price must be PKR 100 to 10,000,000.' }, { status: 400 });
    }

    const appId = 'APP-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const supabaseAdmin = getSupabaseAdmin();

    // Upload photos
    const uploadedPhotoUrls: string[] = [];
    if (photos && photos.length) {
      for (const file of photos) {
        const ext = file.name.split('.').pop()?.toLowerCase();
        const fileName = `${Date.now()}-${crypto.randomBytes(10).toString('hex')}.${ext}`;
        
        const { data, error } = await supabaseAdmin.storage
          .from('uploads')
          .upload(fileName, file, {
            contentType: file.type,
            cacheControl: '3600',
            upsert: false
          });

        if (!error) {
          const { data: publicUrlData } = supabaseAdmin.storage
            .from('uploads')
            .getPublicUrl(fileName);
          uploadedPhotoUrls.push(publicUrlData.publicUrl);
        }
      }
    }

    const appData = {
      id: appId,
      status: 'pending',
      host: { name, phone, cnic: cnicClean, email },
      property: {
        city, type, beds, price: priceVal,
        maxGuests, address, description,
        category, photos: uploadedPhotoUrls,
        amenities: Array.isArray(amenitiesRaw) ? amenitiesRaw.map(a => sanitizeInput(a, 50)) : (amenitiesRaw ? [sanitizeInput(amenitiesRaw as string, 50)] : [])
      }
    };

    const { error: insertError } = await supabaseAdmin.from('applications').insert([appData]);

    if (insertError) {
      console.error('[DB ERROR]', insertError);
      return NextResponse.json({ ok: false, error: 'Database error. Please try again.' }, { status: 500 });
    }

    await sendEmail({
      to: process.env.NOTIFY_EMAIL || process.env.GMAIL_USER!,
      subject: `🏡 HOST APPLICATION [${appId}]`,
      html: `<p>New host application submitted for ${city}.</p>`
    });

    return NextResponse.json({ ok: true, message: "Application received! We'll WhatsApp you.", id: appId });
  } catch (error: any) {
    console.error('[HOST ERROR]', error);
    return NextResponse.json({ ok: false, error: 'Internal server error.' }, { status: 500 });
  }
}
