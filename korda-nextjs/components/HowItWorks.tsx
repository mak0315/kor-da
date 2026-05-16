'use client';

const STEPS = [
  {
    n: 1,
    title: 'Browse',
    desc: 'Search CNIC-verified homes in any sector. Filter by price, amenities, or proximity to hospitals, universities, or business hubs.',
    delay: ''
  },
  {
    n: 2,
    title: 'Book Instantly',
    desc: 'Select dates, book instantly. No hidden fees. Pay in PKR via EasyPaisa, JazzCash, or card through Safepay escrow.',
    delay: 'd1'
  },
  {
    n: 3,
    title: 'Pay Safely',
    desc: 'Your payment is held in Safepay escrow — SBP-licensed — and released to the host only 24 hours after you confirm check-in.',
    delay: 'd2'
  },
  {
    n: 4,
    title: 'Stay Confidently',
    desc: 'Check into your verified home. Dispute within 24 hours if anything is wrong — your money stays protected in escrow.',
    delay: 'd3'
  },
  {
    n: 5,
    title: 'Leave a Review',
    desc: 'After your stay leave a verified review. Dual-blind system — both guest and host review simultaneously. Fair and honest.',
    delay: 'd4'
  }
];

export default function HowItWorks() {
  return (
    <section id="how" className="sec bg-cream" aria-label="How Kor Da works">
      <div className="wrap">
        <div className="sh text-center mb-12">
          <div className="sh-eye flex items-center justify-center gap-3 mb-4">
            <div className="sh-rule w-12 h-px bg-t4"></div>
            <span className="lbl sh-lbl text-t1">The Process</span>
            <div className="sh-rule w-12 h-px bg-t4"></div>
          </div>
          <h2 className="t-h2 text-t1 mb-4">Simple. Safe. Pakistani.</h2>
          <p className="lg-t max-w-2xl mx-auto">Everything in PKR, on WhatsApp the way Pakistani families actually live.</p>
        </div>

        <div className="hsteps grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-6">
          {STEPS.map((step) => (
            <div key={step.n} className={`hstep rv ${step.delay} vis bg-white p-6 rounded-r4 shadow-sm border border-[rgba(28,77,64,0.04)] flex flex-col items-center text-center`}>
              <div className="hstep-n w-10 h-10 bg-tbg text-t1 rounded-full flex items-center justify-center font-bold text-lg mb-4">
                {step.n}
              </div>
              <div className="hstep-t font-serif font-bold text-t1 text-xl mb-3">{step.title}</div>
              <p className="hstep-d text-[0.85rem] text-i3 leading-relaxed">{step.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
