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

  function isPublishable(p) {
    if (!p || typeof p !== 'object') return false;
    if (p.published === false || p.draft === true) return false;
    var status = String(p.status || '').toLowerCase();
    if (status === 'draft' || status === 'unpublished' || status === 'rejected' || status === 'archived') return false;
    return true;
  }

  function normalizeProperty(p) {
    if (!isPublishable(p)) return null;
    if (!p.title) return null;

    var out = {};
    for (var k in p) {
      if (Object.prototype.hasOwnProperty.call(p, k)) out[k] = p[k];
    }

    if (!out.id && !out.slug) {
      out.id = String(out.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'prop-' + Math.random().toString(36).substr(2, 6);
      out.slug = out.id;
    }
    if (!out.id) out.id = out.slug;
    if (!out.slug) out.slug = out.id;

    out.price = parseInt(out.price, 10);
    if (!isFinite(out.price) || out.price < 0) out.price = 0;
    out.baths = parseInt(out.baths, 10);
    if (!isFinite(out.baths) || out.baths < 0) out.baths = 0;
    out.maxGuests = parseInt(out.maxGuests, 10);
    if (!isFinite(out.maxGuests) || out.maxGuests < 1) out.maxGuests = 1;
    out.rating = parseFloat(out.rating);
    if (!isFinite(out.rating) || out.rating < 0) out.rating = 0;
    out.reviews = parseInt(out.reviews, 10);
    if (!isFinite(out.reviews) || out.reviews < 0) out.reviews = 0;

    out.amenities = Array.isArray(out.amenities) ? out.amenities.filter(function(a){ return a != null && String(a).trim(); }) : [];
    out.gallery = Array.isArray(out.gallery) ? out.gallery.filter(function(g){ return g != null && String(g).trim(); }) : [];
    out.landmarks = Array.isArray(out.landmarks) ? out.landmarks.filter(function(l){ return l != null && String(l).trim(); }) : [];

    return out;
  }

  function parsePropertiesPayload(data) {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.properties)) return data.properties;
    return null;
  }

  function getAdminProperties() {
    var adminProps = [];
    try {
      var stored = JSON.parse(localStorage.getItem('kd_admin_myproperties') || '[]');
      if (!Array.isArray(stored)) return adminProps;
      adminProps = stored.filter(function(p) { return p && p.status === 'active'; }).map(function(p) {
        var photos = Array.isArray(p.photos) ? p.photos : [];
        var gallery = photos.map(function(ph) { return ph && (ph.dataUrl || ph); }).filter(Boolean);
        if (p.image && gallery.indexOf(p.image) === -1) gallery.unshift(p.image);
        return {
          id: p.id,
          slug: p.id,
          title: p.name,
          name: p.name,
          type: p.type,
          city: p.area ? (p.area + ', ' + p.city) : p.city,
          area: p.area || p.city,
          address: (p.area ? p.area + ', ' : '') + (p.city || ''),
          price: p.price,
          beds: (p.bedrooms || 1) + ' Bedroom' + (p.bedrooms > 1 ? 's' : ''),
          baths: p.bathrooms || 1,
          maxGuests: p.guests || 2,
          category: 'all',
          featured: !!p.featured,
          rating: 4.8,
          reviews: 0,
          amenities: ['WiFi', 'AC', 'Kitchen'],
          description: p.description || '',
          image: (photos.length > 0 ? photos[0].dataUrl : '') || p.image || '',
          gallery: gallery,
          waContact: p.whatsapp || '923155881733',
          plan: p.plan,
          source: 'admin'
        };
      });
    } catch (e) {}
    return adminProps;
  }

  window.PropertyService = {
    getAll: async function() {
      if (cache) return cache;

      var jsonProps = [];
      try {
        var res = await fetch('/content/compiled/properties.json', { cache: 'no-store' });
        if (res.ok) {
          var data = await res.json();
          var parsed = parsePropertiesPayload(data);
          if (parsed) {
            jsonProps = parsed;
          } else {
            console.warn('PropertyService: Unexpected properties.json structure; showing no compiled listings.');
          }
        } else {
          console.warn('PropertyService: properties.json request failed with status ' + res.status);
        }
      } catch (err) {
        console.warn('PropertyService: Failed to load compiled properties.', err);
      }

      var raw = jsonProps.concat(getAdminProperties());
      var seen = {};
      var normalized = [];
      for (var i = 0; i < raw.length; i++) {
        var item = normalizeProperty(raw[i]);
        if (!item) continue;
        var key = String(item.slug || item.id || '').toLowerCase();
        if (key && seen[key]) continue;
        if (key) seen[key] = true;
        normalized.push(item);
      }

      cache = normalized;
      if (cache.length === 0) {
        console.info('PropertyService: No published properties available.');
      }
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
        if (filters.type && filters.type !== 'all') {
          if ((p.type || '').toLowerCase().indexOf(filters.type.toLowerCase()) === -1) match = false;
        }
        if (filters.keyword) {
          var kw = filters.keyword.toLowerCase();
          var text = (p.title || '') + ' ' + (p.city || '') + ' ' + (p.description || '');
          if (text.toLowerCase().indexOf(kw) === -1) match = false;
        }
        if (filters.maxPrice && p.price > filters.maxPrice) match = false;
        if (filters.minPrice && p.price < filters.minPrice) match = false;
        if (filters.minBeds && p.beds && parseInt(p.beds) < filters.minBeds) match = false;
        if (filters.maxGuests && p.maxGuests && p.maxGuests < filters.maxGuests) match = false;
        return match;
      });
    }
  };
})();
