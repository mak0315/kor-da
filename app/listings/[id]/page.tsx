import { Metadata } from 'next';
import { supabase } from '@/lib/supabase';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import PropertyGallery from '@/components/PropertyGallery';
import BookingForm from '@/components/BookingForm';
import { notFound } from 'next/navigation';

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  const { data: listing } = await supabase
    .from('listings')
    .select('city, category, description')
    .eq('id', id)
    .single();

  if (!listing) return { title: 'Listing Not Found | Kor Da' };

  return {
    title: `${listing.category} in ${listing.city} | Kor Da`,
    description: listing.description?.slice(0, 160),
  };
}

export default async function PropertyPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { data: listing, error } = await supabase
    .from('listings')
    .select('*')
    .eq('id', id)
    .single();

  if (error || !listing) {
    notFound();
  }

  return (
    <main className="min-h-screen bg-s">
      <Navbar />
      
      <div className="pt-24 pb-12">
        <div className="wrap">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
            
            {/* Left Content */}
            <div className="lg:col-span-2 space-y-8">
              <PropertyGallery photos={listing.photos || []} />
              
              <div className="bg-white p-8 rounded-r5 shadow-sm border border-[rgba(28,77,64,0.06)]">
                <div className="flex justify-between items-start mb-6">
                  <div>
                    <span className="lbl text-wa mb-1 block">{listing.category}</span>
                    <h1 className="t-h2 text-t1">{listing.city}</h1>
                    <p className="text-i4 font-bold text-[0.7rem] uppercase tracking-widest mt-2">
                      Verified Host &middot; {listing.type}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-6 py-6 border-y border-tbg2">
                  <div className="text-center">
                    <div className="text-2xl mb-1">👥</div>
                    <div className="text-[0.65rem] font-bold uppercase text-i4">Max Guests</div>
                    <div className="font-serif font-bold text-t1">{listing.maxGuests || 4}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl mb-1">🛏️</div>
                    <div className="text-[0.65rem] font-bold uppercase text-i4">Bedrooms</div>
                    <div className="font-serif font-bold text-t1">{listing.beds || 'Studio'}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl mb-1">✅</div>
                    <div className="text-[0.65rem] font-bold uppercase text-i4">Verified</div>
                    <div className="font-serif font-bold text-t1">Yes</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl mb-1">🛡️</div>
                    <div className="text-[0.65rem] font-bold uppercase text-i4">Escrow</div>
                    <div className="font-serif font-bold text-t1">Protected</div>
                  </div>
                </div>

                <div className="mt-8 space-y-6">
                  <div>
                    <h3 className="font-serif font-bold text-xl text-t1 mb-3">About this stay</h3>
                    <p className="text-i3 leading-relaxed whitespace-pre-line">
                      {listing.description}
                    </p>
                  </div>

                  {listing.amenities && listing.amenities.length > 0 && (
                    <div>
                      <h3 className="font-serif font-bold text-xl text-t1 mb-3">What this place offers</h3>
                      <div className="grid grid-cols-2 gap-3">
                        {listing.amenities.map((item: string, idx: number) => (
                          <div key={idx} className="flex items-center gap-2 text-sm text-i3">
                            <span className="text-wa">✓</span> {item}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Sidebar / Booking Form */}
            <div className="lg:col-span-1">
              <BookingForm listingId={listing.id} pricePerNight={listing.price} />
            </div>

          </div>
        </div>
      </div>

      <Footer />
    </main>
  );
}
