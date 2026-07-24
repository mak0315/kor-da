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
      <div class="lcard rv" data-id="${l.id || l.slug}" data-cat="${l.category || 'all'}" onclick="showPropertyDetail('${(l.id || l.slug).replace(/'/g, "\\'")}', event)" style="cursor:pointer">
        <div class="limg">
          <img src="${imgUrl}" alt="${l.title || l.type}" loading="lazy">
          <button class="lfav ${isSaved ? 'saved' : ''}" onclick="togFav(this);event.stopPropagation()" aria-label="Save Favorite">${isSaved ? '♥' : '♡'}</button>
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
            <button class="btn btn-p btn-sm" onclick="bookNow('${(l.title || l.type).replace(/'/g, "\\'")}', '${fmt(l.price)}');event.stopPropagation()">Book Now</button>
          </div>
        </div>
      </div>
    `;
  };

  window.showPropertyDetail = async function(slug, evt) {
    if (evt && evt.target && (evt.target.closest('.lfav') || evt.target.closest('.btn-p'))) return;
    var prop = await PropertyService.getBySlug(slug);
    if (!prop) return;
    var modal = document.getElementById('pdModal');
    if (!modal) return;
    var imgUrl = (prop.gallery && prop.gallery[0]) ? prop.gallery[0] : (prop.image || 'https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=1200&q=80');
    var amenities = (prop.amenities && prop.amenities.length > 0) ? prop.amenities : ['WiFi','AC','Kitchen'];
    var amenityHtml = amenities.map(function(a){ return '<span class="pd-tag">' + a + '</span>'; }).join('');
    var galleryHtml = '';
    if (prop.gallery && prop.gallery.length > 1) {
      galleryHtml = '<div class="pd-gallery">' + prop.gallery.map(function(g, i) {
        return '<img src="' + g + '" alt="Photo ' + (i+1) + '" loading="lazy" onclick="event.stopPropagation()">';
      }).join('') + '</div>';
    }
    var waMsg = 'Hi Kor Da, I am interested in ' + (prop.title || prop.type) + ' Islamabad. Please share availability and booking details.';
    var waLink = 'https://wa.me/' + (prop.waContact || '923155881733') + '?text=' + encodeURIComponent(waMsg);
    document.getElementById('pdModalBody').innerHTML = `
      <div class="pd-hero-img">
        <img src="${imgUrl}" alt="${prop.title || prop.type}" onclick="event.stopPropagation()">
        <button class="pd-close" onclick="closePD()" aria-label="Close">&times;</button>
        ${prop.featured ? '<div class="pd-feat-badge">Featured</div>' : ''}
      </div>
      <div class="pd-content">
        <div class="pd-main">
          <div class="pd-type">${prop.type || 'Stay'}</div>
          <h2 class="pd-title">${prop.title || prop.type}</h2>
          <p class="pd-loc">📍 ${prop.city || prop.area || 'Islamabad'}${prop.address ? ' · ' + prop.address : ''}</p>
          <div class="pd-meta">
            <div class="pd-meta-item"><div class="pd-meta-label">Beds</div><div class="pd-meta-val">${prop.beds || '1'}</div></div>
            <div class="pd-meta-item"><div class="pd-meta-label">Baths</div><div class="pd-meta-val">${prop.baths || 1}</div></div>
            <div class="pd-meta-item"><div class="pd-meta-label">Guests</div><div class="pd-meta-val">${prop.maxGuests || 2}</div></div>
            <div class="pd-meta-item"><div class="pd-meta-label">Rating</div><div class="pd-meta-val">★ ${prop.rating || '4.9'}</div></div>
          </div>
          <div class="pd-desc">${prop.body || prop.description || 'A comfortable, verified stay in Islamabad.'}</div>
          <h3 class="pd-section-title">Amenities</h3>
          <div class="pd-amenities">${amenityHtml}</div>
          ${galleryHtml}
        </div>
        <div class="pd-sidebar">
          <div class="pd-price-box">
            <div class="pd-price">PKR ${fmt(prop.price)}<span> / night</span></div>
            <a href="${waLink}" target="_blank" rel="noopener" class="pd-wa-btn" onclick="event.stopPropagation()">&#128172; Book via WhatsApp</a>
            <button class="btn btn-p" style="width:100%;margin-top:8px" onclick="bookNow('${(prop.title || prop.type).replace(/'/g, "\\'")}', '${fmt(prop.price)}');event.stopPropagation()">Book Now</button>
            <p class="pd-trust">CNIC-verified host · Safepay escrow · Pay in PKR</p>
          </div>
        </div>
      </div>
    `;
    modal.classList.add('show');
    document.body.style.overflow = 'hidden';
  };

  window.closePD = function() {
    var modal = document.getElementById('pdModal');
    if (modal) { modal.classList.remove('show'); document.body.style.overflow = ''; }
  };

  document.addEventListener('DOMContentLoaded', function() {
    var pdModal = document.getElementById('pdModal');
    if (pdModal) pdModal.addEventListener('click', function(e) { if (e.target === pdModal) closePD(); });
    document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closePD(); });
  });

  /* Reusable Area Card UI Component */
  window.AreaCard = function(area) {
    return `
      <div class="acard rv" onclick="gFilter('${area.name}')">
        <div class="atitle">${area.name}</div>
        ${area.highlight ? '<div class="ahl">' + area.highlight + '</div>' : ''}
        <div class="acount">${area.propertyCount || '10+'} Verified Stays</div>
        <div class="aprice">From PKR ${fmt(area.priceFrom)}/night</div>
      </div>
    `;
  };

  /* Reusable Blog Card UI Component */
  window.BlogCard = function(post) {
    var img = post.image || 'https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=800&q=80';
    var dateStr = post.date ? new Date(post.date).toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' }) : '';
    return `
      <a class="bcard rv" href="/blog/${post.slug}">
        <div class="bimg"><img src="${img}" alt="${post.title}" loading="lazy"></div>
        <div class="bdet">
          <div class="bmeta">${post.category || 'Article'}${dateStr ? ' · ' + dateStr : ''}</div>
          <h3 class="btitle">${post.title}</h3>
          <p class="bexcerpt">${post.excerpt || ''}</p>
        </div>
      </a>
    `;
  };

  /* Reusable Testimonial Card UI Component */
  window.TestimonialCard = function(t) {
    var stars = '';
    for (var i = 0; i < (t.rating || 5); i++) stars += '★';
    return `
      <div class="tcard rv">
        <div class="tstars">${stars}</div>
        <p class="tcontent">"${t.content}"</p>
        <div class="tauthor"><strong>${t.name}</strong>${t.location ? ' · ' + t.location : ''}</div>
      </div>
    `;
  };

  /* Helper for Booking trigger */
  window.bookNow = function(propertyName, price){
    var msg = "Hi Kor Da, I'm interested in " + propertyName + ". Please share availability and booking details.";
    if (price) msg += " (Listed at PKR " + price + "/night)";
    if (typeof openWA === 'function') {
      openWA(msg);
    } else {
      var waNum = window.KORDA_CONFIG ? window.KORDA_CONFIG.waNumber : '923155881733';
      window.open('https://wa.me/' + waNum + '?text=' + encodeURIComponent(msg), '_blank', 'noopener');
    }
  };
})();
