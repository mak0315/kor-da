'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function BookingForm({ listingId, pricePerNight }: { listingId: string, pricePerNight: number }) {
  const router = useRouter();
  const [checkIn, setCheckIn] = useState('');
  const [checkOut, setCheckOut] = useState('');
  const [guests, setGuests] = useState(1);
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // Check session on mount
    const checkSession = async () => {
      const res = await fetch('/api/auth/session'); // I should create this or check via props
      // For now, assume we check on submit
    };
  }, []);

  const calculateTotal = () => {
    if (!checkIn || !checkOut) return 0;
    const diff = new Date(checkOut).getTime() - new Date(checkIn).getTime();
    const nights = Math.ceil(diff / (1000 * 60 * 60 * 24));
    return nights > 0 ? nights * pricePerNight : 0;
  };

  const total = calculateTotal();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('loading');

    try {
      const res = await fetch('/api/bookings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ listingId, checkIn, checkOut, guests }),
      });

      if (res.status === 401) {
        router.push(`/login?next=/listings/${listingId}`);
        return;
      }

      if (res.ok) {
        setStatus('success');
      } else {
        setStatus('error');
      }
    } catch (err) {
      setStatus('error');
    }
  };

  return (
    <div className="bg-white p-6 rounded-r5 shadow-xl border border-[rgba(28,77,64,0.06)] sticky top-24">
      <div className="flex justify-between items-center mb-6">
        <div>
          <span className="text-2xl font-serif font-bold text-t1">PKR {pricePerNight.toLocaleString()}</span>
          <span className="text-sm text-i4 uppercase font-bold ml-1 tracking-wider">/ Night</span>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <label className="text-[0.65rem] font-bold uppercase text-i4" htmlFor="in">Check In</label>
            <input 
              type="date" id="in" required 
              className="w-full p-3 bg-s rounded-r2 text-sm border-none focus:ring-2 focus:ring-t4"
              value={checkIn} onChange={(e) => setCheckIn(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <label className="text-[0.65rem] font-bold uppercase text-i4" htmlFor="out">Check Out</label>
            <input 
              type="date" id="out" required 
              className="w-full p-3 bg-s rounded-r2 text-sm border-none focus:ring-2 focus:ring-t4"
              value={checkOut} onChange={(e) => setCheckOut(e.target.value)}
            />
          </div>
        </div>

        <div className="space-y-1">
          <label className="text-[0.65rem] font-bold uppercase text-i4" htmlFor="guests">Guests</label>
          <select 
            id="guests" className="w-full p-3 bg-s rounded-r2 text-sm border-none focus:ring-2 focus:ring-t4"
            value={guests} onChange={(e) => setGuests(parseInt(e.target.value))}
          >
            {[1,2,3,4,5,6,7,8].map(n => <option key={n} value={n}>{n} Guests</option>)}
          </select>
        </div>

        {total > 0 && (
          <div className="py-4 border-t border-tbg2 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-i3">Stay Duration</span>
              <span className="font-bold">{total / pricePerNight} Nights</span>
            </div>
            <div className="flex justify-between text-lg font-bold text-t1 pt-2 border-t border-tbg2">
              <span>Total Amount</span>
              <span>PKR {total.toLocaleString()}</span>
            </div>
          </div>
        )}

        <button 
          type="submit" 
          disabled={status === 'loading'}
          className="btn btn-p w-full justify-center py-4 text-lg"
        >
          {status === 'loading' ? 'Processing...' : 'Reserve Stay'}
        </button>

        {status === 'success' && (
          <div className="p-4 bg-okbg text-ok rounded-r3 text-center font-bold animate-au">
            🎉 Booking Request Sent!
          </div>
        )}
        {status === 'error' && (
          <div className="p-4 bg-errbg text-err rounded-r3 text-center font-bold animate-au">
            ❌ Booking failed. Please try again.
          </div>
        )}

        <p className="text-[0.65rem] text-center text-i5 uppercase tracking-widest font-bold pt-2">
          Payment via EasyPaisa or JazzCash
        </p>
      </form>
    </div>
  );
}
