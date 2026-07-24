/**
 * KOR DA — CMS RENDERING CONTROLLER (cms.js)
 * Fetches data via PropertyService and renders UI components.
 */
(function(){
  'use strict';

  window.renderListings = function(listings) {
    var lgrid = document.getElementById('lgrid'), 
        le    = document.getElementById('le');
    if (!lgrid) return;

    if (listings && listings.length > 0) {
      lgrid.innerHTML = listings.map(function(l) {
        try { return window.PropertyCard(l); }
        catch(e) { console.warn('PropertyCard render error:', e, l); return ''; }
      }).filter(function(h){ return h; }).join('');
      if (le) le.style.display = 'none';

      /* Re-observe new .rv cards for scroll reveal */
      if (window._rvObs) {
        var newRv = lgrid.querySelectorAll('.rv');
        for (var i = 0; i < newRv.length; i++) {
          window._rvObs.observe(newRv[i]);
        }
      }
    } else {
      lgrid.innerHTML = '';
      if (le) le.style.display = 'block';
    }
  };

  window.loadListings = async function() {
    if (window.PropertyService) {
      var data = await window.PropertyService.getAll();
      window.renderListings(data);
    }
  };

  window.addEventListener('DOMContentLoaded', function(){
    window.loadListings();
  });
})();
