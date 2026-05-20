'use client';

import React, { useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';

export default function LoginForm() {
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
  );
}
