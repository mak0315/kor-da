/**
 * KOR DA — SETTINGS SERVICE (SettingsService.js)
 *
 * Reads homepage/site settings from content/compiled/homepage.json.
 * Migration Boundary: To switch to Supabase/REST, update only this file.
 */
(function(){
  'use strict';

  var cache = null;

  var DEFAULTS = {
    heroLine1: 'Short Stays in',
    heroLine2: 'Pakistan',
    heroLine3: 'You Can Trust',
    heroSubtitle: 'CNIC-verified hosts · Pay in PKR · EasyPaisa & JazzCash. Escrow protection.',
    statLabel1: '20,000+',
    statDesc1: 'STR listings across Pakistan',
    statLabel2: '24hr',
    statDesc2: 'Host approval after CNIC verification'
  };

  window.SettingsService = {
    get: async function() {
      if(cache) return cache;
      try {
        var res = await fetch('content/compiled/homepage.json');
        if(res.ok) {
          var data = await res.json();
          cache = Object.assign({}, DEFAULTS, data);
          return cache;
        }
      } catch(err) {
        console.warn('SettingsService: fetch failed, using defaults', err);
      }
      cache = DEFAULTS;
      return cache;
    }
  };
})();