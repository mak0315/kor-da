'use client';

import Link from 'next/link';

export default function Footer() {
  return (
    <footer className="bg-t0 text-white sec-sm">
      <div className="wrap">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-12">
          <div className="md:col-span-2">
            <div className="flex items-center gap-3 mb-6">
              <div className="nmark bg-white/10 w-10 h-10 flex items-center justify-center rounded-r2">
                <svg viewBox="0 0 20 20" className="w-6 h-6" fill="none">
                  <path d="M10 2L1 8.5V18H6.5V12H13.5V18H19V8.5L10 2Z" fill="white"/>
                  <circle cx="10" cy="9" r="2" fill="#E9A825"/>
                </svg>
              </div>
              <span className="font-serif font-bold text-2xl tracking-tight">Kor Da</span>
            </div>
            <p className="text-white/60 text-sm max-w-sm leading-relaxed mb-8">
              Pakistan's first verified home rental platform. Built locally to redefine hospitality through trust, safety, and transparency.
            </p>
            <div className="flex gap-4">
              <a href="https://instagram.com/korda.pk" className="w-8 h-8 bg-white/5 rounded-full flex items-center justify-center hover:bg-white/10 transition-colors text-lg">📸</a>
              <a href="https://tiktok.com/@kor.da82" className="w-8 h-8 bg-white/5 rounded-full flex items-center justify-center hover:bg-white/10 transition-colors text-lg">🎵</a>
              <a href="https://wa.me/97471259576" className="w-8 h-8 bg-white/5 rounded-full flex items-center justify-center hover:bg-white/10 transition-colors text-lg">💬</a>
            </div>
          </div>

          <div>
            <h4 className="font-bold text-sm uppercase tracking-widest mb-6 text-t4">Explore</h4>
            <ul className="space-y-4 text-sm text-white/70">
              <li><Link href="#listings" className="hover:text-white transition-colors">Browse Stays</Link></li>
              <li><Link href="#how" className="hover:text-white transition-colors">How it Works</Link></li>
              <li><Link href="#categories" className="hover:text-white transition-colors">Stay Types</Link></li>
              <li><Link href="#trust" className="hover:text-white transition-colors">Safety & Trust</Link></li>
            </ul>
          </div>

          <div>
            <h4 className="font-bold text-sm uppercase tracking-widest mb-6 text-t4">Support</h4>
            <ul className="space-y-4 text-sm text-white/70">
              <li><Link href="#faq" className="hover:text-white transition-colors">Common Questions</Link></li>
              <li><Link href="#contact" className="hover:text-white transition-colors">Contact Us</Link></li>
              <li><Link href="#host-form" className="hover:text-white transition-colors">List Your Property</Link></li>
              <li><a href="https://wa.me/97471259576" className="hover:text-white transition-colors">WhatsApp Support</a></li>
            </ul>
          </div>
        </div>

        <div className="h-px bg-white/5 w-full my-12"></div>

        <div className="flex flex-col md:flex-row justify-between items-center gap-6">
          <p className="text-[0.7rem] text-white/40 uppercase tracking-widest font-bold">
            © 2026 Kor Da Islamabad. All Rights Reserved.
          </p>
          <div className="font-urdu text-lg text-white/60">
            آپ کا گھر — ہر جگہ 🇵🇰
          </div>
        </div>
      </div>
    </footer>
  );
}
