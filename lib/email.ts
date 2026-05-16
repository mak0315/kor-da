import nodemailer from 'nodemailer';

const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: { 
    user: process.env.GMAIL_USER, 
    pass: process.env.GMAIL_APP_PASS 
  },
});

export async function sendEmail({ to, subject, html, replyTo }: { to: string, subject: string, html: string, replyTo?: string }) {
  if (!process.env.GMAIL_USER) {
    console.warn('⚠ Set GMAIL_USER + GMAIL_APP_PASS in .env for email functionality');
    return;
  }
  
  try {
    await mailer.sendMail({ 
      from: `"Kor Da" <${process.env.GMAIL_USER}>`, 
      to, 
      subject, 
      html, 
      replyTo 
    });
  } catch (err: any) { 
    console.error('[EMAIL ERROR]', err.message); 
  }
}
