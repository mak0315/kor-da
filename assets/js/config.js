/**
 * KOR DA â€” CENTRAL SITE CONFIGURATION (config.js)
 * 
 * Centralized settings for phone number, WhatsApp number, brand, currency, and location.
 * Updating values here propagates automatically across all UI components and forms.
 */
(function() {
  'use strict';

  window.KORDA_CONFIG = {
    phoneDisplay: "0315-5881733",
    waNumber: "923155881733",
    siteName: "Kor Da",
    siteUrl: "https://www.kordaa.com",
    email: "kordapakistan@gmail.com",
    city: "Islamabad",
    currency: "PKR",
    defaultLanguage: "en",
    launchCity: "Islamabad",
    areas: [
      "F-6", "F-7", "F-8", "F-10", "F-11", 
      "G-8", "G-11", "E-7", "E-11", "DHA", "Bahria Town", "Blue Area"
    ]
  };
})();
