'use client';
import React from 'react';

const CATEGORIES = [
  {
    icon: '🏥',
    title: 'Near Hospital',
    desc: 'Near PIMS, Aga Khan, Shaukat Khanum. G-8, G-9 areas. For families travelling for medical treatment.',
    tag: 'Medical Focus',
    delay: ''
  },
  {
    icon: '👨‍👩‍👧‍👦',
    title: 'Family Stays',
    desc: 'Spacious, private homes for families visiting relatives or needing a full house for groups.',
    tag: 'All Cities',
    delay: 'd1'
  },
  {
    icon: '🎓',
    title: 'Near University',
    desc: 'Near NUST (E-11), COMSATS, QAU, Bahria Uni during admissions and exam seasons.',
    tag: 'Islamabad',
    delay: 'd2'
  },
  {
    icon: '🏔️',
    title: 'Northern Areas',
    desc: 'Murree, Hunza, Naran, Skardu, Swat, Chitral. Mountain retreats in Pakistan\'s beautiful north.',
    tag: 'KPK · GB',
    delay: 'd3'
  },
  {
    icon: '💼',
    title: 'Business Travel',
    desc: 'Near Blue Area, corporate districts. High-speed WiFi, AC, workspace — fully verified hosts.',
    tag: 'Corporate Hubs',
    delay: 'd4'
  },
  {
    icon: '🏢',
    title: 'Govt Posting',
    desc: 'Government employees transferred to Islamabad. 1–3 month stays while settling in.',
    tag: 'Monthly Stays',
    delay: 'd5'
  }
];

export default function StayTypes() {
  return (
    <section id="categories" className="sec bg-s2" aria-label="Stay categories">
      <div className="wrap">
        <div className="sh text-center mb-12">
          <div className="sh-eye flex items-center justify-center gap-3 mb-4">
            <div className="sh-rule w-12 h-px bg-t4"></div>
            <span className="lbl sh-lbl text-t1">Stay Types</span>
            <div className="sh-rule w-12 h-px bg-t4"></div>
          </div>
          <h2 className="t-h2 text-t1 mb-4">Built for Pakistani Needs</h2>
          <p className="lg-t max-w-2xl mx-auto">Categories that don't exist anywhere else, designed around how Pakistani families actually travel.</p>
        </div>

        <div className="cgrid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {CATEGORIES.map((cat, idx) => (
            <div key={idx} className={`cc rv ${cat.delay} vis bg-white p-8 rounded-r5 shadow-sm border border-[rgba(28,77,64,0.06)] transition-all duration-300 hover:-translate-y-1 hover:shadow-md cursor-pointer group`}>
              <span className="cc-e text-3xl mb-4 block group-hover:scale-110 transition-transform inline-block">{cat.icon}</span>
              <div className="cc-t font-serif font-bold text-t1 text-xl mb-3">{cat.title}</div>
              <p className="cc-d text-[0.85rem] text-i3 leading-relaxed mb-4">{cat.desc}</p>
              <span className="cc-c inline-block bg-tbg text-t1 text-[0.65rem] font-bold px-2 py-1 rounded-r2 uppercase tracking-wider">
                {cat.tag}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
