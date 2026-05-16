'use client';

import Image from 'next/image';
import { useState } from 'react';

export default function PropertyGallery({ photos }: { photos: string[] }) {
  const [activePhoto, setActivePhoto] = useState(0);

  if (!photos || photos.length === 0) return null;

  return (
    <div className="space-y-4">
      <div className="relative aspect-[16/9] rounded-r5 overflow-hidden shadow-lg border border-[rgba(28,77,64,0.06)] bg-cream">
        <Image 
          src={photos[activePhoto]} 
          alt={`Property photo ${activePhoto + 1}`}
          fill
          className="object-cover transition-all duration-500"
        />
      </div>
      
      {photos.length > 1 && (
        <div className="grid grid-cols-4 md:grid-cols-6 gap-3">
          {photos.map((photo, idx) => (
            <button 
              key={idx}
              onClick={() => setActivePhoto(idx)}
              className={`relative aspect-square rounded-r2 overflow-hidden border-2 transition-all ${activePhoto === idx ? 'border-t1 shadow-md' : 'border-transparent opacity-60 hover:opacity-100'}`}
            >
              <Image 
                src={photo} 
                alt={`Thumbnail ${idx + 1}`}
                fill
                className="object-cover"
              />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
