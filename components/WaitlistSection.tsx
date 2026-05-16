'use client';

import React, { useState, FormEvent, ChangeEvent } from 'react';

export default function WaitlistSection() {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setStatus('loading');

    try {
      const res = await fetch('/api/waitlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      if (res.ok) {
        setStatus('success');
        setEmail('');
      } else {
        setStatus('error');
      }
    } catch (err) {
      setStatus('error');
    }
  };

  return (
    <section id="waitlist" className="bg-t1 text-white py-24 relative overflow-hidden" aria-label="Join the waitlist">
      <div className="absolute inset-0 opacity-10">
        <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-t4 to-transparent blur-3xl"></div>
      </div>

      <div className="wrap max-w-2xl text-center relative z-10">
        <div className="sh-eye flex items-center justify-center gap-3 mb-6">
          <div className="sh-rule w-10 h-px bg-white/30"></div>
          <span className="lbl text-white/60">Early Access · Islamabad</span>
          <div className="sh-rule w-10 h-px bg-white/30"></div>
        </div>

        <h2 className="t-h2 text-white mb-4">Be First to Book</h2>
        <p className="lg-t text-white/70 mb-10">
          Join the waitlist to be notified at launch + <strong className="text-g3">10% off your first booking</strong>.
        </p>

        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3 max-w-md mx-auto mb-8">
          <input 
            type="email" 
            value={email}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setEmail(e.target.value)}
            required
            placeholder="your@email.com"
            className="flex-1 p-4 rounded-r3 bg-white/10 border border-white/20 text-white placeholder:text-white/40 focus:ring-2 focus:ring-g3 outline-none transition-all"
          />
          <button 
            type="submit" 
            disabled={status === 'loading'}
            className="btn btn-g btn-lg justify-center"
          >
            {status === 'loading' ? 'Joining...' : 'Join Waitlist →'}
          </button>
        </form>

        {status === 'success' && (
          <p className="text-wa font-semibold mb-6 animate-au">🎉 You're on the list! Check your inbox.</p>
        )}
        {status === 'error' && (
          <p className="text-red-400 font-semibold mb-6 animate-au">❌ Failed to join. Please try again.</p>
        )}

        <div className="font-urdu text-xl text-white/40 mb-10">آپ کا گھر — ہر جگہ 🇵🇰</div>

        <div className="flex justify-center gap-6">
          <a href="https://instagram.com/korda.pk" className="text-white/60 hover:text-white transition-colors text-sm font-bold flex items-center gap-2">📸 @korda.pk</a>
          <a href="https://tiktok.com/@kor.da82" className="text-white/60 hover:text-white transition-colors text-sm font-bold flex items-center gap-2">🎵 @kor.da82</a>
        </div>
      </div>
    </section>
  );
}
