/**
 * KOR DA — AREA SERVICE (AreaService.js)
 *
 * Abstraction layer for area/sector data.
 * Migration Boundary: To switch to Supabase/REST, update only this file.
 */
(function(){
  'use strict';

  var cache = null;

  var DEFAULT_AREAS = [
    { id: 'f-7', name: 'F-7 Markaz', slug: 'f7', description: 'Premium diplomatic enclave with top restaurants and shopping. Most popular for corporate travelers.', priceFrom: 4500, propertyCount: 12, highlight: 'Best for business travelers' },
    { id: 'f-11', name: 'F-11 Islamabad', slug: 'f11', description: 'Modern apartment blocks with Margalla Hills views. Great WiFi, ideal for extended stays.', priceFrom: 5000, propertyCount: 8, highlight: 'Scenic Margalla Hills views' },
    { id: 'g-11', name: 'G-11 Islamabad', slug: 'g11', description: 'Close to Metro and markets. Family-friendly with spacious apartments and parking.', priceFrom: 5500, propertyCount: 6, highlight: 'Family-friendly with Metro access' },
    { id: 'e-11', name: 'E-11 (Near NUST)', slug: 'e11', description: 'Affordable studios near NUST and FAST universities. Popular with students and researchers.', priceFrom: 3500, propertyCount: 5, highlight: 'Near NUST & FAST' },
    { id: 'dha', name: 'DHA Islamabad', slug: 'dha', description: 'Gated community with premium villas and apartments. Quiet, secure, and upscale.', priceFrom: 7000, propertyCount: 4, highlight: 'Gated premium community' },
    { id: 'bahria-town', name: 'Bahria Town', slug: 'bahria-town', description: 'Pakistan\'s largest gated community. Amenities, parks, and security. Families love it.', priceFrom: 6000, propertyCount: 7, highlight: 'World-class amenities' }
  ];

  window.AreaService = {
    getAll: async function() {
      if(cache) return cache;
      try {
        var res = await fetch('content/compiled/areas.json');
        if(res.ok) {
          var data = await res.json();
          if(Array.isArray(data) && data.length > 0) { cache = data; return cache; }
        }
      } catch(err) {
        console.warn('AreaService: JSON fetch failed, using fallback', err);
      }
      cache = DEFAULT_AREAS;
      return cache;
    },

    getBySlug: async function(slug) {
      var areas = await this.getAll();
      return areas.find(function(a){ return a.slug === slug || a.id === slug; }) || null;
    }
  };
})();
