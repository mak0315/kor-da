export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-s py-24">
      <div className="wrap max-w-3xl">
        <h1 className="t-h1 text-t1 mb-8">Privacy Policy</h1>
        <div className="prose prose-stone max-w-none space-y-6 text-i3 leading-relaxed">
          <p className="text-sm text-i4 mb-8">Last updated: May 2025</p>

          <h2 className="font-serif font-bold text-xl text-t1">1. Information We Collect</h2>
          <p>When you use Kor Da, we collect information you provide directly to us, such as when you create an account, make a booking, or submit a property application. This includes your name, email address, CNIC number (for hosts), and payment information.</p>

          <h2 className="font-serif font-bold text-xl text-t1">2. How We Use Your Information</h2>
          <p>We use the information we collect to provide, maintain, and improve our services, process bookings and payments, verify host identities through NADRA Verisys, communicate with you about your account and bookings, and ensure platform safety and security.</p>

          <h2 className="font-serif font-bold text-xl text-t1">3. Information Sharing</h2>
          <p>We do not sell your personal information. We share your information only with service providers who assist in our operations (such as Supabase for data storage and Safepay for payment escrow), as required by Pakistani law, or with your consent.</p>

          <h2 className="font-serif font-bold text-xl text-t1">4. Data Security</h2>
          <p>We implement industry-standard security measures to protect your personal information. All payments are processed through Safepay&apos;s SBP-licensed escrow system. CNIC data is verified through NADRA Verisys and stored securely.</p>

          <h2 className="font-serif font-bold text-xl text-t1">5. Your Rights</h2>
          <p>You have the right to access, correct, or delete your personal information. To exercise these rights, contact us at privacy@korda.pk.</p>

          <h2 className="font-serif font-bold text-xl text-t1">6. Contact Us</h2>
          <p>If you have questions about this Privacy Policy, please contact us at privacy@korda.pk or through our contact form.</p>
        </div>
      </div>
    </main>
  );
}
