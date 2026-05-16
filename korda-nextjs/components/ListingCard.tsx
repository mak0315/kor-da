'use client';

import Image from 'next/image';

interface Listing {
  id: string;
  title?: string;
  city: string;
  category: string;
  price: number;
  photos: string[];
  beds?: string;
  maxGuests?: number;
}

export default function ListingCard({ listing }: { listing: Listing }) {
  const mainPhoto = listing.photos?.[0] || 'https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=800&q=80';
  const whatsappUrl = `https://wa.me/97471259576?text=Hi+Kor+Da%2C+I'm+interested+in+the+${listing.category}+in+${listing.city}+(ID:+${listing.id})`;

  return (
    <div className="lcard bg-white rounded-r5 overflow-hidden shadow-sm hover:shadow-lg transition-all duration-300 border border-[rgba(28,77,64,0.06)] group">
      <div className="lc-top relative aspect-[4/3] overflow-hidden">
        <Image 
          src={mainPhoto} 
          alt={listing.category}
          fill
          className="object-cover transition-transform duration-700 group-hover:scale-110"
        />
        <div className="absolute top-3 left-3 bg-white/90 backdrop-blur-sm px-2 py-1 rounded-r2 text-[0.65rem] font-bold text-t1 uppercase tracking-wider flex items-center gap-1">
          <span className="w-1.5 h-1.5 bg-wa rounded-full animate-pulse"></span>
          Verified
        </div>
        <div className="absolute bottom-3 right-3 bg-t1/80 backdrop-blur-md text-white px-3 py-1.5 rounded-r3 text-sm font-bold">
          PKR {listing.price.toLocaleString()} <span className="text-[0.6rem] opacity-80 uppercase">/ Night</span>
        </div>
      </div>
      
      <div className="lc-info p-5">
        <div className="flex justify-between items-start mb-2">
          <div>
            <span className="lbl text-wa mb-1 block">{listing.category}</span>
            <h3 className="t-h3 text-t1 line-clamp-1">{listing.city}</h3>
          </div>
        </div>
        
        <div className="flex items-center gap-4 text-[0.8rem] text-i3 mb-4">
          <div className="flex items-center gap-1">🛏️ {listing.beds || 'Studio'}</div>
          <div className="flex items-center gap-1">👥 {listing.maxGuests || 2} Guests</div>
        </div>
        
        <div className="h-px bg-[rgba(28,77,64,0.06)] w-full mb-4"></div>
        
        <a 
          href={whatsappUrl} 
          target="_blank" 
          rel="noopener"
          className="btn btn-o w-full justify-center group-hover:bg-t1 group-hover:text-white group-hover:border-t1"
        >
          Book via WhatsApp
        </a>
      </div>
    </div>
  );
}
