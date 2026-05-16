'use client';

import React, { useState } from 'react';
import Link from 'next/link';

export default function SignupPage() {
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setStatus('loading');
    setError('');
    setMessage('');

    const formData = new FormData(e.currentTarget);
    const data = Object.fromEntries(formData.entries());

    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      const result = await res.json();

      if (res.ok) {
        setStatus('success');
        setMessage(result.message || 'Account created successfully!');
      } else {
        setStatus('error');
        setError(result.error || 'Failed to create account.');
      }
    } catch (err) {
      setStatus('error');
      setError('An unexpected error occurred.');
    }
  };

  return (
    <main className="min-h-screen bg-cream flex items-center justify-center p-6">
      <div className="max-w-md w-full bg-white p-10 rounded-r6 shadow-xl border border-[rgba(28,77,64,0.06)]">
        <div className="text-center mb-10">
          <Link href="/" className="inline-block mb-6">
            <div className="nmark bg-t1 w-12 h-12 flex items-center justify-center rounded-r2 mx-auto">
              <svg viewBox="0 0 20 20" className="w-8 h-8" fill="none">
                <path d="M10 2L1 8.5V18H6.5V12H13.5V18H19V8.5L10 2Z" fill="white"/>
                <circle cx="10" cy="9" r="2" fill="#E9A825"/>
              </svg>
            </div>
          </Link>
          <h1 className="t-h2 text-t1 mb-2">Join Kor Da</h1>
          <p className="text-i4 text-sm font-medium">Create an account to book verified stays across Pakistan.</p>
        </div>

        {status === 'success' ? (
          <div className="text-center space-y-6 animate-au">
            <div className="text-5xl">📩</div>
            <h3 className="t-h3 text-t1">Check your email</h3>
            <p className="text-i3 leading-relaxed">
              We've sent a confirmation link to your email. Please click it to activate your account.
            </p>
            <Link href="/login" className="btn btn-p w-full justify-center">Go to Login →</Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-1">
              <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="email">Email Address</label>
              <input 
                type="email" id="email" name="email" required 
                className="w-full p-4 bg-s rounded-r3 outline-none focus:ring-2 focus:ring-t4 transition-all"
                placeholder="name@example.com"
              />
            </div>
            <div className="space-y-1">
              <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="password">Password</label>
              <input 
                type="password" id="password" name="password" required minLength={6}
                className="w-full p-4 bg-s rounded-r3 outline-none focus:ring-2 focus:ring-t4 transition-all"
                placeholder="Minimum 6 characters"
              />
            </div>

            <button 
              type="submit" 
              disabled={status === 'loading'}
              className={`btn btn-p w-full justify-center py-5 text-lg ${status === 'loading' ? 'opacity-70 cursor-not-allowed' : ''}`}
            >
              {status === 'loading' ? 'Creating Account...' : 'Sign Up Free →'}
            </button>

            {status === 'error' && (
              <div className="p-4 bg-errbg text-err rounded-r3 text-center text-sm font-bold animate-au">
                ❌ {error}
              </div>
            )}
          </form>
        )}

        <div className="mt-10 pt-10 border-t border-tbg text-center">
          <p className="text-sm text-i4">
            Already have an account? {' '}
            <Link href="/login" className="text-t1 font-bold hover:underline">Log in here</Link>
          </p>
        </div>
      </div>
    </main>
  );
}
