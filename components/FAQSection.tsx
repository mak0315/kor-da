'use client';
import React, { useState } from 'react';

const FAQS = [
  {
    q: 'How do I pay? Can I use EasyPaisa?',
    a: 'Yes — EasyPaisa is our primary payment method. We also accept JazzCash, debit/credit cards, and bank transfer. All payments in PKR through Safepay escrow (SBP-licensed). No USD, no foreign fees.'
  },
  {
    q: 'How does Safepay escrow protect me?',
    a: 'Your payment goes into Safepay escrow and is held until 24 hours after check-in. If you dispute within 24 hours, the money stays in escrow until resolved. Hosts cannot receive payment before you are satisfied.'
  },
  {
    q: 'How are hosts CNIC-verified?',
    a: 'Every host\'s CNIC is verified against NADRA\'s official Verisys database before their listing goes live. Only a registered Pakistani company can access Verisys — this is one of Kor Da\'s key safety advantages.'
  },
  {
    q: 'Which areas of Islamabad are covered?',
    a: 'All Islamabad sectors (F-5 to F-11, G-6 to G-15, E-7, E-11, I-8, I-10, etc.), all DHA and Bahria Town phases, Blue Area, Bani Gala, and Gulberg Greens. Rawalpindi areas are also covered.'
  },
  {
    q: 'What commission does Kor Da charge?',
    a: 'Kor Da charges hosts 9% only on completed bookings — the lowest in Pakistan. Zero listing fee, zero monthly cost. You keep 91%, paid after guest checks in.'
  },
  {
    q: 'What if something is wrong with my stay?',
    a: 'File a dispute within 24 hours of check-in via WhatsApp. We respond same day. If the property doesn\'t match the listing, you get a full refund from escrow.'
  }
];

export default function FAQSection() {
  const [openIdx, setOpenIdx] = useState<number | null>(0);

  return (
    <section id="faq" className="sec bg-cream" aria-label="FAQ">
      <div className="wrap max-w-3xl">
        <div className="sh text-center mb-12">
          <div className="sh-eye flex items-center justify-center gap-3 mb-4">
            <div className="sh-rule w-12 h-px bg-t4"></div>
            <span className="lbl sh-lbl text-t1">FAQ</span>
            <div className="sh-rule w-12 h-px bg-t4"></div>
          </div>
          <h2 className="t-h2 text-t1 mb-4">Common Questions</h2>
        </div>

        <div className="faq-list space-y-4">
          {FAQS.map((faq, idx) => (
            <div key={idx} className="faq-item border border-[rgba(28,77,64,0.08)] bg-white rounded-r3 overflow-hidden">
              <button 
                className="faq-q w-full flex justify-between items-center p-5 text-left font-serif font-bold text-t1 hover:bg-tbg/30 transition-colors"
                onClick={() => setOpenIdx(openIdx === idx ? null : idx)}
              >
                <span>{faq.q}</span>
                <span className={`text-2xl transition-transform ${openIdx === idx ? 'rotate-45' : ''}`}>+</span>
              </button>
              {openIdx === idx && (
                <div className="faq-a p-5 pt-0 text-[0.9rem] text-i3 leading-relaxed animate-au">
                  {faq.a}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
