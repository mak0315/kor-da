'use client';

import { useState } from 'react';

export default function ContactSection() {
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setStatus('loading');
    
    const formData = new FormData(e.currentTarget);
    const data = Object.fromEntries(formData.entries());

    try {
      const res = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (res.ok) {
        setStatus('success');
        (e.target as HTMLFormElement).reset();
      } else {
        setStatus('error');
      }
    } catch (err) {
      setStatus('error');
    }
  };

  return (
    <section id="contact" className="sec bg-s2" aria-label="Contact Kor Da">
      <div className="wrap">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
          <div>
            <div className="sh mb-8">
              <div className="sh-eye flex items-center gap-3 mb-4">
                <div className="sh-rule w-12 h-px bg-t4"></div>
                <span className="lbl sh-lbl text-t1">Contact</span>
              </div>
              <h2 className="t-h2 text-t1 mb-4">Get in Touch</h2>
              <p className="lg-t">Partnerships, investments, hosting, or just want to say salam? We reply within 2 hours.</p>
            </div>

            <div className="space-y-6">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-white rounded-full flex items-center justify-center shadow-sm">💬</div>
                <div>
                  <div className="text-[0.7rem] uppercase font-bold text-i4 tracking-widest">WhatsApp</div>
                  <a href="https://wa.me/97471259576" className="font-bold text-t1 text-lg hover:text-wa transition-colors">+974 7125 9576</a>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-white rounded-full flex items-center justify-center shadow-sm">✉️</div>
                <div>
                  <div className="text-[0.7rem] uppercase font-bold text-i4 tracking-widest">Email Support</div>
                  <a href="mailto:ah5909931@gmail.com" className="font-bold text-t1 text-lg hover:text-wa transition-colors">ah5909931@gmail.com</a>
                </div>
              </div>
            </div>
            
            <div className="mt-10 p-6 bg-t1 text-white rounded-r4 shadow-lg">
              <h4 className="font-serif font-bold text-lg mb-2">Available for Support</h4>
              <p className="text-sm opacity-80 leading-relaxed">Our team is active on WhatsApp from 9 AM to 12 AM PKT for guest and host inquiries.</p>
            </div>
          </div>

          <div className="bg-white p-8 rounded-r5 shadow-sm border border-[rgba(28,77,64,0.06)]">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="name">Name</label>
                  <input type="text" id="name" name="name" required className="w-full p-3 bg-s rounded-r2 border-none focus:ring-2 focus:ring-t4 transition-all" placeholder="Your Name" />
                </div>
                <div className="space-y-1">
                  <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="email">Email</label>
                  <input type="email" id="email" name="email" required className="w-full p-3 bg-s rounded-r2 border-none focus:ring-2 focus:ring-t4 transition-all" placeholder="your@email.com" />
                </div>
              </div>
              <div className="space-y-1">
                <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="subject">Subject</label>
                <input type="text" id="subject" name="subject" required className="w-full p-3 bg-s rounded-r2 border-none focus:ring-2 focus:ring-t4 transition-all" placeholder="Inquiry about..." />
              </div>
              <div className="space-y-1">
                <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="message">Message</label>
                <textarea id="message" name="message" required rows={4} className="w-full p-3 bg-s rounded-r2 border-none focus:ring-2 focus:ring-t4 transition-all" placeholder="Tell us more..."></textarea>
              </div>

              <button 
                type="submit" 
                disabled={status === 'loading'}
                className={`btn btn-p w-full justify-center ${status === 'loading' ? 'opacity-70 cursor-not-allowed' : ''}`}
              >
                {status === 'loading' ? 'Sending...' : 'Send Message'}
              </button>

              {status === 'success' && (
                <div className="p-3 bg-okbg text-ok rounded-r2 text-sm font-semibold text-center animate-au">
                  🎉 Message sent! We'll reply shortly.
                </div>
              )}
              {status === 'error' && (
                <div className="p-3 bg-errbg text-err rounded-r2 text-sm font-semibold text-center animate-au">
                  ❌ Failed to send message. Please WhatsApp us.
                </div>
              )}
            </form>
          </div>
        </div>
      </div>
    </section>
  );
}
