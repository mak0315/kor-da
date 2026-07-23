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
        return window.PropertyCard(l);
      }).join('');
      if (le) le.style.display = 'none';
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
