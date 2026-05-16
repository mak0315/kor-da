'use client';
import React from 'react';

const TRUST_POINTS = [
  {
    icon: '🆔',
    title: 'CNIC-Verified Hosts',
    desc: 'Every host\'s CNIC is verified against NADRA database before their listing goes live. No anonymous landlords — ever.',
    delay: ''
  },
  {
    icon: '🔒',
    title: 'Safepay Escrow (SBP)',
    desc: 'Your payment is held by Safepay — SBP-licensed — until 24 hours after check-in. Hosts cannot receive funds before you are satisfied.',
    delay: 'd1'
  },
  {
    icon: '💰',
    title: 'EasyPaisa & JazzCash',
    desc: 'Pay in PKR your way. No USD, no foreign fees, no complications. EasyPaisa, JazzCash, debit card, or bank transfer accepted.',
    delay: 'd2'
  },
  {
    icon: '⚖️',
    title: '24-Hour Disputes',
    desc: 'Something wrong? Dispute via WhatsApp within 24 hours. We respond same day and hold funds until resolved.',
    delay: 'd3'
  },
  {
    icon: '⭐',
    title: 'Verified Reviews Only',
    desc: 'Only guests who completed paid bookings can leave reviews. Dual-blind system ensures fair and honest feedback.',
    delay: 'd4'
  },
  {
    icon: '💸',
    title: '9% Commission',
    desc: 'Lowest in Pakistan. Hosts keep 91%. No upfront costs, commission is only deducted after a successful booking.',
    delay: 'd5'
  }
];

export default function TrustSection() {
  return (
    <section id="trust" className="sec bg-cream" aria-label="Why choose Kor Da">
      <div className="wrap">
        <div className="sh text-center mb-12">
          <div className="sh-eye flex items-center justify-center gap-3 mb-4">
            <div className="sh-rule w-12 h-px bg-t4"></div>
            <span className="lbl sh-lbl text-t1">Why Kor Da</span>
            <div className="sh-rule w-12 h-px bg-t4"></div>
          </div>
          <h2 className="t-h2 text-t1 mb-4">Safety You Can Verify</h2>
          <p className="lg-t max-w-2xl mx-auto">Not just promises — actual verification systems. Every protection enforced, not just stated.</p>
        </div>

        <div className="tgrid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {TRUST_POINTS.map((point, idx) => (
            <div key={idx} className={`tc rv ${point.delay} vis flex flex-col items-center text-center p-4`}>
              <div className="tc-icon text-3xl mb-4 bg-white w-16 h-16 flex items-center justify-center rounded-full shadow-sm border border-[rgba(28,77,64,0.04)]">
                {point.icon}
              </div>
              <div className="tc-t font-serif font-bold text-t1 text-lg mb-2">{point.title}</div>
              <p className="tc-d text-[0.85rem] text-i3 leading-relaxed">{point.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
