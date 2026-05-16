'use client';
import React from 'react';

import { useState, useEffect } from 'react';
import Link from 'next/link';

const BACKGROUND_IMAGES = [
  "https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=1920&q=80",
  "https://images.unsplash.com/photo-1600585154340-be6161a56a0c?auto=format&fit=crop&w=1920&q=80",
  "https://images.unsplash.com/photo-1600607687940-4e524cb35a3a?auto=format&fit=crop&w=1920&q=80",
  "https://images.unsplash.com/photo-1600566753190-17f0bb2a6c3e?auto=format&fit=crop&w=1920&q=80",
  "https://images.unsplash.com/photo-1600210492486-724fe5c67fb0?auto=format&fit=crop&w=1920&q=80",
  "https://images.unsplash.com/photo-1600573472591-ee6b68d14c68?auto=format&fit=crop&w=1920&q=80"
];

export default function Hero() {
  const [currentSlide, setCurrentSlide] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentSlide((prev: number) => (prev + 1) % BACKGROUND_IMAGES.length);
    }, 5000);
    return () => clearInterval(timer);
  }, []);

  return (
    <section id="hero" aria-label="Kor Da Pakistan verified home rental">
      <div className="hss" aria-hidden="true">
        {BACKGROUND_IMAGES.map((img, idx) => (
          <div 
            key={idx} 
            className={`hs transition-opacity duration-1000 ${currentSlide === idx ? 'opacity-100' : 'opacity-0'}`}
            style={{ backgroundImage: `url(${img})`, position: 'absolute', inset: 0, backgroundSize: 'cover', backgroundPosition: 'center' }}
          ></div>
        ))}
      </div>
      <div className="hov" aria-hidden="true"></div>
      
      <div className="hcon">
        <div className="hleft">
          <div className="hey au">
            <div className="heyd"></div>
            <span>Pakistan's Verified Home Rental Platform</span>
          </div>
          <h1 className="t-h1 htitle au al1">
            <span className="l1">Short Stays in</span>
            <span className="l2 text-g3">Pakistan</span>
            <span className="l3">You Can Trust</span>
          </h1>
          <p className="hsub au al2">
            CNIC-verified hosts · Pay in PKR · EasyPaisa & JazzCash Escrow protection. 
            All over Pakistan: Islamabad, Karachi, Lahore, Peshawar, Quetta and beyond.
          </p>
          <div className="hbtns au al3">
            <Link href="#listings" className="btn btn-w btn-lg">🔍 Browse Stays</Link>
            <Link href="#host-form" className="btn btn-ghost btn-lg">🏠 List Free</Link>
          </div>
          <div className="htrust au al4">
            <div className="hti"><div className="hticon">🆔</div><span>CNIC Verified</span></div>
            <div className="hti"><div className="hticon">🔒</div><span>Escrow</span></div>
            <div className="hti"><div className="hticon">💰</div><span>EasyPaisa</span></div>
            <div className="hti"><div className="hticon">💬</div><span>WhatsApp</span></div>
          </div>
          <p className="hurdu au al4 font-urdu" dir="rtl">آپ کا گھر — ہر جگہ</p>
        </div>

        <div className="hscard au al2">
          <div className="hsc-title text-t1 font-serif">Find your stay in Pakistan</div>
          
          <div className="hsc-field">
            <div className="hsc-lbl">Area / Sector</div>
            <select className="hsc-inp" id="hCity" aria-label="Select area">
              <option value="">All areas...</option>
              <optgroup label="Islamabad — Elite Sectors">
                <option value="F-7">F-7, Islamabad</option>
                <option value="F-6">F-6, Islamabad</option>
                <option value="F-10">F-10, Islamabad</option>
                <option value="DHA">DHA Islamabad</option>
              </optgroup>
              <optgroup label="Major Cities">
                <option value="Lahore">Lahore</option>
                <option value="Karachi">Karachi</option>
                <option value="Peshawar">Peshawar</option>
              </optgroup>
            </select>
          </div>

          <div className="hsc-dates flex gap-3">
            <div className="hsc-field flex-1">
              <div className="hsc-lbl">Check in</div>
              <input type="date" className="hsc-inp w-full" id="hIn" />
            </div>
            <div className="hsc-field flex-1">
              <div className="hsc-lbl">Check out</div>
              <input type="date" className="hsc-inp w-full" id="hOut" />
            </div>
          </div>

          <div className="hsc-field">
            <div className="hsc-lbl">Guests</div>
            <select className="hsc-inp" id="hGuests">
              <option>1 guest</option>
              <option>2 guests</option>
              <option selected>3–4 guests</option>
              <option>5–6 guests</option>
              <option>7+ guests</option>
            </select>
          </div>

          <button className="hsc-btn w-full btn-p mt-2" aria-label="Search">🔍 Search Stays</button>
          
          <div className="hsc-div my-3 text-center text-i4">or</div>
          
          <a href="https://wa.me/97471259576" target="_blank" rel="noopener" className="hsc-wa flex items-center justify-center gap-2 bg-[#25D366] text-white p-3 rounded-r3 font-bold">
            💬 WhatsApp to Find a Stay
          </a>
          <div className="hsc-pay mt-4 text-[0.7rem] text-center text-i4 uppercase tracking-wider">
            EasyPaisa · JazzCash · Card · Bank Transfer
          </div>
        </div>
      </div>

      <div className="hdots flex justify-center gap-2 absolute bottom-8 left-0 right-0 z-10">
        {BACKGROUND_IMAGES.map((_, idx) => (
          <button 
            key={idx}
            className={`hd w-2 h-2 rounded-full transition-all ${currentSlide === idx ? 'bg-white scale-125' : 'bg-white/40'}`}
            onClick={() => setCurrentSlide(idx)}
            aria-label={`Go to slide ${idx + 1}`}
          ></button>
        ))}
      </div>
    </section>
  );
}
