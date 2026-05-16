'use client';

export default function StatsBar() {
  return (
    <div className="sbar sec-sm bg-white" aria-label="Platform stats">
      <div className="wrap">
        <div className="sg grid grid-cols-2 md:grid-cols-4 gap-8">
          <div className="si flex flex-col items-center text-center">
            <div className="sn text-[2rem] font-serif font-bold text-t1 leading-tight">20,000+</div>
            <div className="sl text-[0.85rem] text-i3 uppercase tracking-wider">STR listings<br/>across Pakistan</div>
          </div>
          <div className="si flex flex-col items-center text-center">
            <div className="sn text-[2rem] font-serif font-bold text-t1 leading-tight">9%</div>
            <div className="sl text-[0.85rem] text-i3 uppercase tracking-wider">Commission — lowest<br/>in Pakistan</div>
          </div>
          <div className="si flex flex-col items-center text-center">
            <div className="sn text-[2rem] font-serif font-bold text-t1 leading-tight">24hr</div>
            <div className="sl text-[0.85rem] text-i3 uppercase tracking-wider">Host approval after<br/>CNIC verification</div>
          </div>
          <div className="si flex flex-col items-center text-center">
            <div className="sn text-[2rem] font-serif font-bold text-t1 leading-tight">PKR</div>
            <div className="sl text-[0.85rem] text-i3 uppercase tracking-wider">EasyPaisa · JazzCash<br/>Safepay escrow</div>
          </div>
        </div>
      </div>
    </div>
  );
}
