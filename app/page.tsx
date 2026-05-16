'use client';

import React, { useState } from 'react';
import Navbar from '@/components/Navbar';
import Hero from '@/components/Hero';
import StatsBar from '@/components/StatsBar';
import ListingsStrip from '@/components/ListingsStrip';
import ListingsGrid from '@/components/ListingsGrid';
import HowItWorks from '@/components/HowItWorks';
import StayTypes from '@/components/StayTypes';
import TrustSection from '@/components/TrustSection';
import AboutSection from '@/components/AboutSection';
import HostForm from '@/components/HostForm';
import FAQSection from '@/components/FAQSection';
import WaitlistSection from '@/components/WaitlistSection';
import ContactSection from '@/components/ContactSection';
import Footer from '@/components/Footer';

export default function Home() {
  const [activeArea, setActiveArea] = useState('');

  return (
    <main className="min-h-screen">
      <Navbar />
      <Hero />
      <StatsBar />
      
      <ListingsStrip 
        activeArea={activeArea} 
        onAreaChange={setActiveArea} 
      />

      <ListingsGrid city={activeArea} />
      
      <HowItWorks />
      <StayTypes />
      <TrustSection />
      
      <AboutSection />
      <HostForm />
      <FAQSection />
      <WaitlistSection />
      <ContactSection />
      
      <Footer />
    </main>
  );
}
