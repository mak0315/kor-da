/**
 * KOR DA — PROPERTY SERVICE (PropertyService.js)
 * 
 * Abstraction layer for fetching and searching property listings.
 * Reads compiled Decap CMS data (/content/compiled/properties.json).
 * 
 * Migration Boundary: UI components call PropertyService exclusively.
 * To migrate to Supabase / GraphQL, update this file only!
 */
(function(){
  'use strict';

  var cache = null;

  var DEFAULT_PROPERTIES = [
    {
      id: 'luxury-studio-f7-islamabad',
      slug: 'luxury-studio-f7-islamabad',
      title: 'Luxury Studio — F-7 Markaz',
      type: 'Studio / 1-Bed',
      city: 'F-7, Islamabad',
      area: 'F-7',
      address: 'F-7 Markaz, Islamabad',
      price: 4500,
      beds: 'Studio',
      baths: 1,
      maxGuests: 2,
      category: 'business',
      featured: true,
      rating: 4.9,
      reviews: 23,
      amenities: ['WiFi','AC','Kitchen','TV','Geyser'],
      description: 'Modern fully-furnished studio in the heart of F-7 Markaz. 5 min walk to Jinnah Super Market, restaurants and shopping.',
      image: 'https://images.unsplash.com/photo-1560448204-e02f11c3d0e2?auto=format&fit=crop&w=800&q=75',
      gallery: ['https://images.unsplash.com/photo-1560448204-e02f11c3d0e2?auto=format&fit=crop&w=800&q=75'],
      waContact: '923155881733'
    },
    {
      id: 'family-apartment-g11-islamabad',
      slug: 'family-apartment-g11-islamabad',
      title: '2-Bed Family Apartment — G-11',
      type: 'Full Apartment',
      city: 'G-11, Islamabad',
      area: 'G-11',
      address: 'G-11/1, Islamabad',
      price: 7000,
      beds: '2 Bedrooms',
      baths: 2,
      maxGuests: 5,
      category: 'family',
      featured: false,
      rating: 4.8,
      reviews: 15,
      amenities: ['WiFi','AC','Kitchen','Parking','UPS/Generator','Geyser','TV'],
      description: 'Spacious 2-bedroom apartment ideal for families. Fully equipped kitchen, close to Metro station and G-11 Markaz.',
      image: 'https://images.unsplash.com/photo-1502005229762-cf1b2da7c5d6?auto=format&fit=crop&w=800&q=75',
      gallery: ['https://images.unsplash.com/photo-1502005229762-cf1b2da7c5d6?auto=format&fit=crop&w=800&q=75'],
      waContact: '923155881733'
    },
    {
      id: 'modern-apartment-f11-islamabad',
      slug: 'modern-apartment-f11-islamabad',
      title: 'Modern 2-Bed Apartment — F-11',
      type: 'Full Apartment',
      city: 'F-11, Islamabad',
      area: 'F-11',
      address: 'F-11 Markaz, Islamabad',
      price: 6500,
      beds: '2 Bedrooms',
      baths: 2,
      maxGuests: 4,
      category: 'business',
      featured: true,
      rating: 4.9,
      reviews: 31,
      amenities: ['WiFi','AC','Kitchen','Parking','UPS/Generator','TV','Balcony'],
      description: 'Contemporary apartment in F-11 Markaz with scenic Margalla Hills view. Fast WiFi, dedicated workspace.',
      image: 'https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=800&q=75',
      gallery: ['https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=800&q=75'],
      waContact: '923155881733'
    },
    {
      id: 'studio-e11-near-nust',
      slug: 'studio-e11-near-nust',
      title: 'Cozy Studio — E-11 (Near NUST)',
      type: 'Studio / 1-Bed',
      city: 'E-11, Islamabad',
      area: 'E-11',
      address: 'E-11/2, Islamabad',
      price: 3800,
      beds: 'Studio',
      baths: 1,
      maxGuests: 2,
      category: 'budget',
      featured: false,
      rating: 4.7,
      reviews: 18,
      amenities: ['WiFi','AC','Kitchen','TV'],
      description: 'Affordable studio apartment near NUST and FAST universities. Ideal for students, travelers, and short stays.',
      image: 'https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?auto=format&fit=crop&w=800&q=75',
      gallery: ['https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?auto=format&fit=crop&w=800&q=75'],
      waContact: '923155881733'
    }
  ];

  window.PropertyService = {
    getAll: async function() {
      if (cache) return cache;
      try {
        var res = await fetch('content/compiled/properties.json');
        if (res.ok) {
          var data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            cache = data;
            return cache;
          }
        }
      } catch (err) {
        console.warn('PropertyService: JSON fetch failed, using fallback static data', err);
      }
      cache = DEFAULT_PROPERTIES;
      return cache;
    },

    getBySlug: async function(slug) {
      var properties = await this.getAll();
      return properties.find(function(p){ return p.slug === slug || p.id === slug; }) || null;
    },

    getFeatured: async function() {
      var properties = await this.getAll();
      return properties.filter(function(p){ return p.featured; });
    },

    search: async function(filters) {
      var properties = await this.getAll();
      if (!filters) return properties;

      return properties.filter(function(p) {
        var match = true;
        if (filters.category && filters.category !== 'all') {
          if (p.category !== filters.category) match = false;
        }
        if (filters.area && filters.area !== 'all') {
          var loc = (p.city || '') + ' ' + (p.area || '');
          if (loc.toLowerCase().indexOf(filters.area.toLowerCase()) === -1) match = false;
        }
        if (filters.keyword) {
          var kw = filters.keyword.toLowerCase();
          var text = (p.title || '') + ' ' + (p.city || '') + ' ' + (p.description || '');
          if (text.toLowerCase().indexOf(kw) === -1) match = false;
        }
        if (filters.maxPrice && p.price > filters.maxPrice) match = false;
        if (filters.minBeds && p.beds && parseInt(p.beds) < filters.minBeds) match = false;
        return match;
      });
    }
  };
})();
