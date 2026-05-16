'use client';

const STATS = [
  { n: '15K+', l: 'Instagram Followers' },
  { n: '2', l: 'Startups Founded' },
  { n: '1', l: 'Book Published' },
  { n: 'KPK', l: 'Havelian, Pakistan' }
];

const LINKS = [
  { icon: '📸', label: '@korda.pk', url: 'https://www.instagram.com/korda.pk' },
  { icon: '🤳', label: '@stupid._soul', url: 'https://www.instagram.com/stupid._soul' },
  { icon: '🎵', label: 'TikTok', url: 'https://www.tiktok.com/@kor.da82' },
  { icon: '💼', label: 'LinkedIn', url: 'https://www.linkedin.com/company/kor-da/' },
  { icon: '💬', label: 'WhatsApp', url: 'https://wa.me/97471259576' },
  { icon: '✉️', label: 'Email', url: 'mailto:ah5909931@gmail.com' }
];

export default function AboutSection() {
  return (
    <section id="about" className="sec bg-s" aria-label="About the founder">
      <div className="wrap">
        <div className="agrid grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div className="aimg rv vis relative">
            <div className="aspect-[4/5] rounded-r6 overflow-hidden shadow-xl border-8 border-white">
              <img 
                src="https://hebbkx1anhila5yf.public.blob.usercontent.com/Founder%20and%20ceo-IUK8mZfC9e9iV3V3Y3V3V3V3V3V3V3.png" 
                alt="Muhammad Ayan Khan - Founder & CEO" 
                className="w-full h-full object-cover"
              />
            </div>
            <div className="absolute -bottom-6 -right-6 bg-t1 text-white p-6 rounded-r4 shadow-lg hidden md:block max-w-[240px]">
              <p className="text-sm font-medium italic">"Kor Da was built to make the experience local, simple, and fair."</p>
            </div>
          </div>
          
          <div className="rv d1 vis">
            <div className="sh-eye flex items-center gap-3 mb-6">
              <div className="sh-rule w-12 h-px bg-t4"></div>
              <span className="lbl sh-lbl text-t1">Founder & CEO</span>
            </div>
            <h2 className="t-h1 text-ink mb-6">Muhammad <br /><em className="text-t1 not-italic">Ayan Khan</em></h2>
            
            <div className="space-y-4 text-i3 leading-relaxed mb-8">
              <p className="lg-t">
                I built Kor Da because most existing platforms were built for foreign markets, not for how people in Pakistan actually travel. 
                Payments in dollars, heavy deductions, and support that doesn't understand local culture.
              </p>
              <p>
                As a Pakistani, I saw how frustrating this is. Families traveling for medical treatment, business, or tourism have different needs. 
                Kor Da is designed around Pakistani people, hospitality, and the realities of our market.
              </p>
              <p>
                My journey spans continents — from serving as a Security Officer in Qatar to being a published author and photographer. 
                Kor Da is my most personal project, built from lived experience.
              </p>
            </div>

            <div className="astats grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
              {STATS.map((stat, idx) => (
                <div key={idx} className="astat text-center">
                  <div className="astat-n text-t1 font-serif font-bold text-xl">{stat.n}</div>
                  <div className="astat-l text-[0.65rem] text-i4 uppercase tracking-wider">{stat.l}</div>
                </div>
              ))}
            </div>

            <div className="alinks flex flex-wrap gap-4">
              {LINKS.map((link, idx) => (
                <a 
                  key={idx} 
                  href={link.url} 
                  target="_blank" 
                  rel="noopener" 
                  className="alink flex items-center gap-2 text-sm font-semibold text-t1 hover:text-t2 transition-colors border-b border-tbg2 pb-1"
                >
                  <span>{link.icon}</span> {link.label}
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
