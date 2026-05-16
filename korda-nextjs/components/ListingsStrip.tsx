'use client';

const AREAS = [
  { label: 'All Pakistan', value: '' },
  { label: 'F-7 Markaz', value: 'F-7' },
  { label: 'F-6 Markaz', value: 'F-6' },
  { label: 'F-8', value: 'F-8' },
  { label: 'F-10', value: 'F-10' },
  { label: 'F-11', value: 'F-11' },
  { label: 'DHA', value: 'DHA' },
  { label: 'Bahria Town', value: 'Bahria' },
  { label: 'Lahore', value: 'Lahore' },
  { label: 'Karachi', value: 'Karachi' },
];

export default function ListingsStrip({ activeArea, onAreaChange }: { activeArea: string, onAreaChange: (val: string) => void }) {
  return (
    <div className="astrip border-y border-[rgba(28,77,64,0.08)] bg-white/50 backdrop-blur-sm sticky top-[70px] z-[890]" aria-label="Browse by area">
      <div className="wrap py-4">
        <p className="lbl text-i4 mb-2">Browse by area</p>
        <div className="astrip-inner flex items-center gap-2 overflow-x-auto no-scrollbar pb-1">
          {AREAS.map((area) => (
            <button
              key={area.value}
              onClick={() => onAreaChange(area.value)}
              className={`atag whitespace-nowrap px-4 py-2 rounded-rf text-[0.85rem] font-semibold transition-all duration-[var(--d1)]
                ${activeArea === area.value 
                  ? 'bg-t1 text-white shadow-md' 
                  : 'bg-white text-t1 border border-[rgba(28,77,64,0.1)] hover:bg-tbg'}
              `}
            >
              {area.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
