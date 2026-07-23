/**
 * KOR DA — REUSABLE UI CARD RENDERERS (property.js)
 * Component functions for rendering Property, Blog, Area, and Testimonial cards.
 */
(function(){
  'use strict';

  function fmt(n){ return parseInt(n).toLocaleString('en-PK'); }

  /* Reusable Property Card UI Component */
  window.PropertyCard = function(l) {
    var imgUrl = (l.gallery && l.gallery[0]) ? l.gallery[0] : (l.image || 'https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=800&q=80');
    var isSaved = (typeof favs !== 'undefined' && favs.has) ? favs.has(l.id || l.slug) : false;
    
    return `
      <div class="lcard rv" data-id="${l.id || l.slug}" data-cat="${l.category || 'all'}">
        <div class="limg">
          <img src="${imgUrl}" alt="${l.title || l.type}" loading="lazy">
          <button class="lfav ${isSaved ? 'saved' : ''}" onclick="togFav(this)" aria-label="Save Favorite">${isSaved ? '♥' : '♡'}</button>
          ${l.featured ? '<div class="lbadge">Featured</div>' : ''}
        </div>
        <div class="ldet">
          <div class="ltop">
            <span class="ltype">${l.type || 'Stay'}</span>
            <div class="lrate">★ ${l.rating || '4.9'}</div>
          </div>
          <h3 class="lname">${l.title || (l.beds + ' Bed ' + l.type)}</h3>
          <p class="lloc">📍 ${l.city || l.area || 'Islamabad'}</p>
          <div class="lbot">
            <div class="lprice"><strong>PKR ${fmt(l.price)}</strong> / night</div>
            <button class="btn btn-p btn-sm" onclick="bookNow('${(l.title || l.type).replace(/'/g, "\\'")}', '${fmt(l.price)}')">Book Now</button>
          </div>
        </div>
      </div>
    `;
  };

  /* Reusable Area Card UI Component */
  window.AreaCard = function(area) {
    return `
      <div class="acard rv" onclick="gFilter('${area.name}')">
        <div class="atitle">${area.name}</div>
        <div class="acount">${area.count || '10+'} Verified Stays</div>
      </div>
    `;
  };

  /* Helper for Booking trigger */
  window.bookNow = function(propertyName, price){
    var msg = "Hi Kor Da, I'm interested in " + propertyName + ". Please share availability and booking details.";
    if (price) msg += " (Listed at PKR " + price + "/night)";
    if (typeof openWA === 'function') {
      openWA(msg);
    }
  };
})();
