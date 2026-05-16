'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { createClient } from '@/lib/supabase/client';
import { useRouter } from 'next/navigation';

export default function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [user, setUser] = useState<any>(null);
  const supabase = createClient();
  const router = useRouter();

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    
    // Check initial session
    const getSession = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      setUser(session?.user ?? null);
    };
    getSession();

    // Listen for changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });

    return () => {
      window.removeEventListener('scroll', handleScroll);
      subscription.unsubscribe();
    };
  }, []);

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    setUser(null);
    router.refresh();
  };

  const toggleDrawer = () => setIsDrawerOpen(!isDrawerOpen);

  return (
    <>
      <nav 
        id="nav" 
        className={`${isScrolled ? 'sc' : ''}`}
        role="navigation" 
        aria-label="Main navigation"
      >
        <Link href="/" className="nlogo" aria-label="Kor Da Home">
          <div className="nmark">
            <svg viewBox="0 0 20 20" fill="none">
              <path d="M10 2L1 8.5V18H6.5V12H13.5V18H19V8.5L10 2Z" fill="white"/>
              <circle cx="10" cy="9" r="2" fill="#E9A825"/>
            </svg>
          </div>
          <span className="nname text-white">Kor Da</span>
        </Link>

        <div className="nlinks hidden lg:flex" role="menubar">
          <Link href="/#listings" className="nl">Explore</Link>
          <Link href="/#how" className="nl">How it Works</Link>
          <Link href="/#categories" className="nl">Stay Types</Link>
          <Link href="/#about" className="nl">About</Link>
          <Link href="/#faq" className="nl">FAQ</Link>
          <Link href="/#contact" className="nl">Contact</Link>
        </div>

        <div className="nacts hidden md:flex">
          <a href="https://www.instagram.com/korda.pk" target="_blank" rel="noopener" className="nsoc" aria-label="Instagram">📸</a>
          <a href="https://wa.me/97471259576" target="_blank" rel="noopener" className="nsoc" aria-label="WhatsApp">💬</a>
          <Link href="/#host-form" className="nhost">List Property</Link>
          {user ? (
            <button onClick={handleLogout} className="btn btn-sm btn-o !text-white border-white/20">Logout</button>
          ) : (
            <Link href="/login" className="btn btn-sm btn-p">Login</Link>
          )}
        </div>

        <button 
          className={`nhbg ${isDrawerOpen ? 'open' : ''} flex lg:hidden`} 
          onClick={toggleDrawer}
          aria-label="Toggle menu"
        >
          <span></span><span></span><span></span>
        </button>
      </nav>

      {/* Overlay */}
      <div 
        className={`novl ${isDrawerOpen ? 'on' : ''}`} 
        onClick={toggleDrawer}
        aria-hidden="true"
      ></div>

      {/* Drawer */}
      <div className={`ndr ${isDrawerOpen ? 'open' : ''}`} role="dialog" aria-label="Navigation">
        <button className="ndx" onClick={toggleDrawer} aria-label="Close menu">✕</button>
        
        <Link href="#listings" className="ndl" onClick={toggleDrawer}>🔍 Explore Stays</Link>
        <Link href="#how" className="ndl" onClick={toggleDrawer}>📋 How it Works</Link>
        <Link href="#categories" className="ndl" onClick={toggleDrawer}>🏠 Stay Types</Link>
        <Link href="#trust" className="ndl" onClick={toggleDrawer}>🔒 Safety & Trust</Link>
        <Link href="#about" className="ndl" onClick={toggleDrawer}>👤 About Founder</Link>
        <Link href="#faq" className="ndl" onClick={toggleDrawer}>❓ FAQ</Link>
        <Link href="#contact" className="ndl" onClick={toggleDrawer}>✉️ Contact</Link>
        
        <div className="ndiv"></div>
        
        <Link href="#host-form" className="ndl" onClick={toggleDrawer}>🏠 List Your Property</Link>
        <Link href="#earnings" className="ndl" onClick={toggleDrawer}>💰 Earnings Calculator</Link>
        <Link href="#waitlist" className="ndl" onClick={toggleDrawer}>📨 Join Waitlist</Link>
        
        <div className="ndiv"></div>
        
        <a href="https://www.instagram.com/korda.pk" target="_blank" rel="noopener" className="ndl">📸 @korda.pk Instagram</a>
        <a href="https://www.tiktok.com/@kor.da82" target="_blank" rel="noopener" className="ndl">🎵 @kor.da82 TikTok</a>
        <a href="https://www.linkedin.com/company/kor-da/" target="_blank" rel="noopener" className="ndl">💼 Kor Da LinkedIn</a>
        
        <div className="ndiv"></div>
        
        <a href="https://wa.me/97471259576" target="_blank" rel="noopener" className="btn btn-p mt-[10px] justify-center text-center">
          💬 WhatsApp Support
        </a>
      </div>
    </>
  );
}
