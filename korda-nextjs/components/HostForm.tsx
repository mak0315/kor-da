'use client';

import React, { useState, ChangeEvent, FormEvent } from 'react';

export default function HostForm() {
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [files, setFiles] = useState<File[]>([]);

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFiles(Array.from(e.target.files));
    }
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setStatus('loading');
    
    const formData = new FormData(e.currentTarget);

    try {
      const res = await fetch('/api/host', {
        method: 'POST',
        body: formData, // Send as multipart/form-data
      });

      if (res.ok) {
        setStatus('success');
        (e.target as HTMLFormElement).reset();
        setFiles([]);
      } else {
        setStatus('error');
      }
    } catch (err) {
      setStatus('error');
    }
  };

  return (
    <section id="host-form" className="sec bg-s" aria-label="List your property">
      <div className="wrap">
        <div className="sh text-center mb-12">
          <div className="sh-eye flex items-center justify-center gap-3 mb-4">
            <div className="sh-rule w-12 h-px bg-t4"></div>
            <span className="lbl sh-lbl text-t1">For Hosts</span>
            <div className="sh-rule w-12 h-px bg-t4"></div>
          </div>
          <h2 className="t-h2 text-t1 mb-4">List Your Property Free</h2>
          <p className="lg-t max-w-2xl mx-auto">Zero listing fee. 9% only on completed bookings. Every host is CNIC-verified.</p>
        </div>

        <div className="max-w-4xl mx-auto bg-white p-8 md:p-12 rounded-r6 shadow-xl border border-[rgba(28,77,64,0.06)]">
          <form onSubmit={handleSubmit} className="space-y-10">
            {/* Section: Your Details */}
            <div className="space-y-6">
              <h3 className="text-t1 font-serif font-bold text-xl pb-2 border-b border-tbg">Your Details</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-1">
                  <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="hN">Full Name *</label>
                  <input type="text" id="hN" name="name" required className="w-full p-3 bg-s rounded-r2 outline-none focus:ring-2 focus:ring-t4" placeholder="Muhammad Ali" />
                </div>
                <div className="space-y-1">
                  <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="hPh">WhatsApp Number *</label>
                  <input type="tel" id="hPh" name="phone" required className="w-full p-3 bg-s rounded-r2 outline-none focus:ring-2 focus:ring-t4" placeholder="+92 3XX XXX XXXX" />
                </div>
                <div className="space-y-1">
                  <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="hCn">CNIC Number *</label>
                  <input type="text" id="hCn" name="cnic" required className="w-full p-3 bg-s rounded-r2 outline-none focus:ring-2 focus:ring-t4" placeholder="00000-0000000-0" />
                  <p className="text-[0.6rem] text-i4 italic mt-1">Verified via NADRA Verisys</p>
                </div>
                <div className="space-y-1">
                  <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="hEm">Email</label>
                  <input type="email" id="hEm" name="email" className="w-full p-3 bg-s rounded-r2 outline-none focus:ring-2 focus:ring-t4" placeholder="your@email.com" />
                </div>
              </div>
            </div>

            {/* Section: Property Details */}
            <div className="space-y-6">
              <h3 className="text-t1 font-serif font-bold text-xl pb-2 border-b border-tbg">Property Details</h3>
              <div className="space-y-6">
                <div className="space-y-1">
                  <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="hAd">Full Address *</label>
                  <input type="text" id="hAd" name="address" required className="w-full p-3 bg-s rounded-r2 outline-none focus:ring-2 focus:ring-t4" placeholder="House/Flat No., Street, Sector / Area" />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="space-y-1">
                    <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="hAr">City / Area *</label>
                    <select id="hAr" name="city" required className="w-full p-3 bg-s rounded-r2 outline-none focus:ring-2 focus:ring-t4 appearance-none">
                      <option value="">Select city...</option>
                      <option value="Islamabad">Islamabad</option>
                      <option value="Rawalpindi">Rawalpindi</option>
                      <option value="Lahore">Lahore</option>
                      <option value="Karachi">Karachi</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="hTy">Property Type *</label>
                    <select id="hTy" name="type" required className="w-full p-3 bg-s rounded-r2 outline-none focus:ring-2 focus:ring-t4 appearance-none">
                      <option value="">Select type...</option>
                      <option>Full Apartment</option>
                      <option>Studio / 1-Bed</option>
                      <option>House / Bungalow</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label className="text-[0.7rem] font-bold uppercase text-i4" htmlFor="hPr">Price / Night (PKR) *</label>
                    <input type="number" id="hPr" name="price" required className="w-full p-3 bg-s rounded-r2 outline-none focus:ring-2 focus:ring-t4" placeholder="e.g. 5000" />
                  </div>
                </div>
              </div>
            </div>

            {/* Section: Photos */}
            <div className="space-y-6">
              <h3 className="text-t1 font-serif font-bold text-xl pb-2 border-b border-tbg">Photos</h3>
              <div className="p-10 border-2 border-dashed border-tbg2 rounded-r4 text-center hover:bg-tbg/20 transition-colors cursor-pointer relative">
                <input 
                  type="file" 
                  id="photos" 
                  name="photos" 
                  multiple 
                  accept="image/*" 
                  onChange={handleFileChange}
                  className="absolute inset-0 opacity-0 cursor-pointer"
                />
                <div className="text-3xl mb-2">📸</div>
                <div className="font-bold text-t1">Click or drag photos here</div>
                <p className="text-[0.7rem] text-i4 mt-1 uppercase tracking-widest">Min 3 photos recommended</p>
                {files.length > 0 && (
                  <p className="mt-4 text-wa font-bold text-sm">✅ {files.length} photos selected</p>
                )}
              </div>
            </div>

            {/* Agreement & Submit */}
            <div className="space-y-6 pt-6">
              <label className="flex gap-3 items-start cursor-pointer text-sm text-i3 leading-relaxed">
                <input type="checkbox" required className="mt-1 accent-t1 w-4 h-4" />
                <span>I confirm this property is mine or I am authorized to list it. I agree to Kor Da's 9% commission on completed bookings only. My CNIC will be verified via NADRA before my listing goes live.</span>
              </label>

              <button 
                type="submit" 
                disabled={status === 'loading'}
                className={`btn btn-p btn-xl w-full justify-center py-5 text-lg ${status === 'loading' ? 'opacity-70 cursor-not-allowed' : ''}`}
              >
                {status === 'loading' ? 'Submitting Application...' : 'Submit Host Application →'}
              </button>

              {status === 'success' && (
                <div className="p-4 bg-okbg text-ok rounded-r3 text-center font-bold animate-au shadow-sm">
                  🏠 Application Received! We'll WhatsApp you within 24 hours.
                </div>
              )}
              {status === 'error' && (
                <div className="p-4 bg-errbg text-err rounded-r3 text-center font-bold animate-au shadow-sm">
                  ❌ Error submitting application. Please try again or WhatsApp support.
                </div>
              )}
            </div>
          </form>
        </div>
      </div>
    </section>
  );
}
