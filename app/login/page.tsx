'use client';

import React, { useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';



function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [error, setError] = useState('');
  const next = searchParams.get('next') || '/';

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setStatus('loading');
    setError('');
    const formData = new FormData(e.currentTarget);
    const data = Object.fromEntries(formData.entries());
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      const result = await res.json();
      if (res.ok) {
        setStatus('success');
        router.push(next);
        router.refresh();
      } else {
        setStatus('error');
        setError(result.error || 'Invalid credentials');
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
                <path d="M10 2L1 8.5V18H6.5V12H13.5V18H19V8.5L10 2Z" fill="white" />
                <circle cx="10" cy="9" r="2" fill="#E9A825" />
              </svg>
            </div>
          </Link>
          <h1 className="t-h2 text-t1 mb-2">Welcome Back</h1>
          <p className="text-i4 text-sm font-medium">Log in to manage your stays and bookings.</p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-1">
            <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="email">Email Address</label>
            <input
              type="email"
              id="email"
              name="email"
              required
              className="w-full p-4 bg-s rounded-r3 outline-none focus:ring-2 focus:ring-t4 transition-all"
              placeholder="name@example.com"
            />
          </div>
          <div className="space-y-1">
            <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              required
              className="w-full p-4 bg-s rounded-r3 outline-none focus:ring-2 focus:ring-t4 transition-all"
              placeholder="••••••••"
            />
          </div>
          <button
            type="submit"
            disabled={status === 'loading'}
            className={`btn btn-p w-full justify-center py-5 text-lg ${status === 'loading' ? 'opacity-70 cursor-not-allowed' : ''}`}
          >
            {status === 'loading' ? 'Logging in...' : 'Log In →'}
          </button>
          {status === 'error' && (
            <div className="p-4 bg-errbg text-err rounded-r3 text-center text-sm font-bold animate-au">
              ❌ {error}
            </div>
          )}
        </form>
        <div className="mt-10 pt-10 border-t border-tbg text-center">
          <p className="text-sm text-i4">
            Don't have an account?{' '}
            <Link href="/signup" className="text-t1 font-bold hover:underline">Create one free</Link>
          </p>
        </div>
      </div>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginContent />
    </Suspense>
  );
}
