import type { Metadata } from 'next';
import { Playfair_Display } from 'next/font/google';
import { Plus_Jakarta_Sans } from 'next/font/google';
import { Noto_Nastaliq_Urdu } from 'next/font/google';
import './globals.css';

const playfair = Playfair_Display({ 
  subsets: ['latin'],
  variable: '--font-playfair',
  weight: ['500', '600', '700', '800'],
});

const jakarta = Plus_Jakarta_Sans({ 
  subsets: ['latin'],
  variable: '--font-jakarta',
  weight: ['300', '400', '500', '600', '700'],
});

const urdu = Noto_Nastaliq_Urdu({
  subsets: ['arabic'],
  variable: '--font-urdu',
  weight: ['400'],
});

export const metadata: Metadata = {
  title: 'Kor Da | Verified Short Stays in Pakistan | Book in PKR | EasyPaisa Accepted',
  description: "Kor Da — Pakistan's verified home rental platform. Book verified short stays in Islamabad and all sectors. Pay in PKR via EasyPaisa. CNIC-verified hosts, Safepay escrow protection.",
  keywords: "short stay Pakistan, daily rental islamabad, furnished flat islamabad, rent by day islamabad, f-7 short stay, bahria town short stay, dha islamabad rental, verified home rental islamabad, korda, kor da, easypais rental islamabad",
  openGraph: {
    title: 'Kor Da — Verified Short Stays in Islamabad | Pay in PKR',
    description: "CNIC-verified hosts · EasyPaisa & JazzCash · Safepay escrow · All Islamabad areas. Pakistan's trusted home rental platform.",
    type: 'website',
    url: 'https://korda.pk',
  },
  twitter: {
    card: 'summary_large_image',
  },
};

export const viewport = {
  themeColor: '#1C4D40',
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${playfair.variable} ${jakarta.variable} ${urdu.variable}`}>
      <body className="font-sans antialiased text-ink bg-s">
        {children}
        <div id="modal-root"></div>
      </body>
    </html>
  );
}
