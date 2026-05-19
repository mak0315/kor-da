'use client';

import { useState, useEffect } from 'react';
import ListingCard from './ListingCard';

export default function ListingsGrid({ city = '', category = 'all' }: { city?: string, category?: string }) {
  const [listings, setListings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchListings() {
      setLoading(true);
      try {
        const res = await fetch(`/api/listings?city=${city}&category=${category}`);
        const data = await res.json();
        if (data.ok) {
          setListings(data.listings);
        } else {
          setError(data.error);
        }
      } catch (err) {
        setError('Failed to load listings');
      } finally {
        setLoading(false);
      }
    }

    fetchListings();
  }, [city, category]);

  if (loading) {
    return (
      <div className="sec wrap text-center py-20">
        <div className="inline-block w-8 h-8 border-4 border-t1 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-i4">Finding verified stays...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="sec wrap text-center py-20 text-err">
        <p>⚠️ {error}</p>
      </div>
    );
  }

  if (listings.length === 0) {
    return (
      <div className="sec wrap text-center py-20">
        <div className="text-4xl mb-4">🏠</div>
        <h3 className="t-h3 text-t1">No stays found in this area</h3>
        <p className="lg-t mt-2">Try choosing "All Pakistan" or contact us on WhatsApp.</p>
        <a href="https://wa.me/97471259576" target="_blank" rel="noopener" className="btn btn-p mt-6">
          WhatsApp Support
        </a>
      </div>
    );
  }

  return (
    <section id="listings" className="sec wrap">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 lg:gap-8">
        {listings.map((listing: any) => (
          <ListingCard key={listing.id} listing={listing} />
        ))}
      </div>
    </section>
  );
}
