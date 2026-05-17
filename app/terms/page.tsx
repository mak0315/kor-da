export default function TermsPage() {
  return (
    <main className="min-h-screen bg-s py-24">
      <div className="wrap max-w-3xl">
        <h1 className="t-h1 text-t1 mb-8">Terms of Service</h1>
        <div className="prose prose-stone max-w-none space-y-6 text-i3 leading-relaxed">
          <p className="text-sm text-i4 mb-8">Last updated: May 2025</p>

          <h2 className="font-serif font-bold text-xl text-t1">1. Acceptance of Terms</h2>
          <p>By accessing or using Kor Da, you agree to be bound by these Terms of Service and all applicable Pakistani laws and regulations. If you do not agree with any of these terms, you are prohibited from using this platform.</p>

          <h2 className="font-serif font-bold text-xl text-t1">2. Platform Services</h2>
          <p>Kor Da provides a marketplace connecting property hosts and guests in Islamabad and surrounding areas. We verify host identities through NADRA Verisys and process payments through Safepay&apos;s SBP-licensed escrow system.</p>

          <h2 className="font-serif font-bold text-xl text-t1">3. Host Obligations</h2>
          <p>Hosts must provide accurate CNIC information for verification, maintain properties as described in their listings, honour confirmed bookings, and comply with all local laws regarding short-term rentals in Pakistan.</p>

          <h2 className="font-serif font-bold text-xl text-t1">4. Guest Obligations</h2>
          <p>Guests must treat properties with respect, honour the check-in and check-out times, report any issues within 24 hours of check-in to be eligible for dispute resolution, and comply with the host&apos;s house rules.</p>

          <h2 className="font-serif font-bold text-xl text-t1">5. Payments and Commission</h2>
          <p>All payments are processed in PKR through Safepay escrow. Kor Da charges hosts a 9% commission on completed bookings only. Payments are released to hosts 24 hours after guest check-in, subject to no active disputes.</p>

          <h2 className="font-serif font-bold text-xl text-t1">6. Dispute Resolution</h2>
          <p>Disputes must be filed within 24 hours of check-in via WhatsApp. Kor Da will investigate and resolve disputes within 48 hours. Our decisions regarding escrow release are final.</p>

          <h2 className="font-serif font-bold text-xl text-t1">7. Contact</h2>
          <p>For questions about these Terms, contact us at legal@korda.pk or through our contact form.</p>
        </div>
      </div>
    </main>
  );
}
