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
    var cardId = l.id || l.slug || (l.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'property-' + Math.random().toString(36).substr(2,6);
    
    return `
      <div class="lcard rv" data-id="${cardId}" data-cat="${l.category || 'all'}" onclick="showPropertyDetail('${cardId.replace(/'/g, "\\'")}', event)" style="cursor:pointer">
        <div class="limg">
          <img src="${imgUrl}" alt="${l.title || l.type}" loading="lazy">
          <button class="lfav ${isSaved ? 'saved' : ''}" onclick="togFav(this);event.stopPropagation()" aria-label="Save Favorite">${isSaved ? '♥' : '♡'}</button>
          <button class="lshare" onclick="shareProperty('${(l.title || l.type).replace(/'/g, "\\'")}', '${cardId.replace(/'/g, "\\'")}', event)" aria-label="Share property"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></button>
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
    if (!prop) { prop = (await PropertyService.getAll()).find(function(p) {
      return (p.id || p.slug || '').toLowerCase() === (slug || '').toLowerCase() ||
             (p.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') === slug;
    }); }
    if (!prop) return;
    var modal = document.getElementById('pdModal');
    if (!modal) return;
    var allImages = [];
    if (prop.image) allImages.push(prop.image);
    if (prop.gallery && prop.gallery.length) {
      prop.gallery.forEach(function(g) { if (allImages.indexOf(g) === -1) allImages.push(g); });
    }
    if (allImages.length === 0) allImages.push('https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=1200&q=80');
    window._pdImages = allImages;
    var imgCount = allImages.length;
    var imgCounter = imgCount > 1 ? '<span class="pd-img-count">1/' + imgCount + '</span>' : '';
    var scrollGallery = '<div class="pd-scroll-gallery">' + allImages.map(function(g, i) {
      return '<img src="' + g + '" alt="Photo ' + (i+1) + '" loading="' + (i === 0 ? 'eager' : 'lazy') + '" onclick="openImgZoom(this)" data-idx="' + i + '">';
    }).join('') + '</div>';
    var amenities = (prop.amenities && prop.amenities.length > 0) ? prop.amenities : ['WiFi','AC','Kitchen'];
    var amenityHtml = amenities.map(function(a){ return '<span class="pd-tag">' + a + '</span>'; }).join('');
    var waMsg = 'Hi Kor Da, I am interested in ' + (prop.title || prop.type) + ' Islamabad. Please share availability and booking details.';
    var waLink = 'https://wa.me/' + (prop.waContact || '923155881733') + '?text=' + encodeURIComponent(waMsg);
    document.getElementById('pdModalBody').innerHTML = `
      <button class="pd-close" onclick="closePD()" aria-label="Close">&times;</button>
      <button class="pd-share" onclick="shareProperty('${(prop.title || prop.type).replace(/'/g, "\\'")}', '${(prop.id || prop.slug || '').replace(/'/g, "\\'")}')" aria-label="Share property"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></button>
      ${prop.featured ? '<div class="pd-feat-badge">Featured</div>' : ''}
      ${imgCounter}
      ${scrollGallery}
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
    var scrollEl = modal.querySelector('.pd-scroll-gallery');
    if (scrollEl) {
      scrollEl.addEventListener('scroll', function() {
        var idx = Math.round(scrollEl.scrollLeft / scrollEl.offsetWidth);
        var counter = modal.querySelector('.pd-img-count');
        if (counter && imgCount > 1) counter.textContent = (idx + 1) + '/' + imgCount;
      });
    }
    modal.classList.add('show');
    document.body.style.overflow = 'hidden';
  };

  window.closePD = function() {
    var modal = document.getElementById('pdModal');
    if (modal) { modal.classList.remove('show'); document.body.style.overflow = ''; }
  };

  window.openImgZoom = function(img) {
    var overlay = document.getElementById('imgZoom');
    if (!overlay) return;
    var imgs = window._pdImages || [img.src];
    var idx = parseInt(img.getAttribute('data-idx')) || 0;
    window._zoomIdx = idx;
    window._zoomScale = 1;
    var zi = document.getElementById('imgZoomEl');
    if (zi) { zi.src = imgs[idx]; zi.style.transform = 'scale(1)'; zi.style.transition = 'transform .2s ease'; }
    var cnt = document.getElementById('imgZoomCount');
    if (cnt) cnt.textContent = imgs.length > 1 ? (idx + 1) + ' / ' + imgs.length : '';
    overlay.classList.add('show');
    var prev = document.getElementById('imgZoomPrev');
    var next = document.getElementById('imgZoomNext');
    if (prev) prev.style.display = imgs.length > 1 ? 'flex' : 'none';
    if (next) next.style.display = imgs.length > 1 ? 'flex' : 'none';
  };

  window.slideImg = function(dir) {
    var imgs = window._pdImages;
    if (!imgs || imgs.length < 2) return;
    window._zoomIdx = ((window._zoomIdx || 0) + dir + imgs.length) % imgs.length;
    window._zoomScale = 1;
    var zi = document.getElementById('imgZoomEl');
    if (zi) { zi.src = imgs[window._zoomIdx]; zi.style.transform = 'scale(1)'; zi.style.transition = 'transform .2s ease'; }
    var cnt = document.getElementById('imgZoomCount');
    if (cnt) cnt.textContent = (window._zoomIdx + 1) + ' / ' + imgs.length;
  };

  window.closeImgZoom = function() {
    var overlay = document.getElementById('imgZoom');
    if (overlay) overlay.classList.remove('show');
  };

  window.zoomImg = function(e) {
    var zi = document.getElementById('imgZoomEl');
    if (!zi) return;
    if (e.deltaY < 0) window._zoomScale = Math.min(3, (window._zoomScale || 1) + 0.15);
    else window._zoomScale = Math.max(0.5, (window._zoomScale || 1) - 0.15);
    zi.style.transform = 'scale(' + window._zoomScale + ')';
    zi.style.transition = 'transform .15s ease';
  };

  document.addEventListener('DOMContentLoaded', function() {
    var pdModal = document.getElementById('pdModal');
    if (pdModal) pdModal.addEventListener('click', function(e) { if (e.target === pdModal) closePD(); });
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') { closeImgZoom(); closePD(); }
      if (document.getElementById('imgZoom') && document.getElementById('imgZoom').classList.contains('show')) {
        if (e.key === 'ArrowLeft') slideImg(-1);
        if (e.key === 'ArrowRight') slideImg(1);
      }
    });

    var imgZoomEl = document.getElementById('imgZoomEl');
    if (imgZoomEl) {
      imgZoomEl.addEventListener('wheel', zoomImg, { passive: true });
      var lastDist = 0;
      var swipeStartX = 0, swipeStartY = 0, swiping = false;
      imgZoomEl.addEventListener('touchstart', function(e) {
        if (e.touches.length === 2) {
          lastDist = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
        } else if (e.touches.length === 1) {
          swipeStartX = e.touches[0].clientX;
          swipeStartY = e.touches[0].clientY;
          swiping = true;
        }
      });
      imgZoomEl.addEventListener('touchmove', function(e) {
        if (e.touches.length === 2) {
          swiping = false;
          e.preventDefault();
          var dist = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
          var scale = (dist / lastDist) * (window._zoomScale || 1);
          window._zoomScale = Math.max(0.5, Math.min(3, scale));
          imgZoomEl.style.transform = 'scale(' + window._zoomScale + ')';
          imgZoomEl.style.transition = 'none';
          lastDist = dist;
        } else if (e.touches.length === 1 && swiping) {
          var dx = e.touches[0].clientX - swipeStartX;
          var dy = e.touches[0].clientY - swipeStartY;
          if (Math.abs(dy) > 10 && Math.abs(dy) > Math.abs(dx)) {
            swiping = false;
          }
          if (Math.abs(dx) > 30 && Math.abs(dx) > Math.abs(dy) * 1.5) {
            swiping = false;
            slideImg(dx < 0 ? 1 : -1);
          }
        }
      }, { passive: false });
      imgZoomEl.addEventListener('touchend', function() { swiping = false; });
    }
    var imgZoomBg = document.getElementById('imgZoom');
    if (imgZoomBg) imgZoomBg.addEventListener('click', function(e) { if (e.target === imgZoomBg) closeImgZoom(); });
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

  /* Helper — Share Property */
  window.shareProperty = function(title, slug, evt) {
    if (evt) evt.stopPropagation();
    var url = window.location.origin + '/#property=' + encodeURIComponent(slug);
    var text = 'Check out ' + title + ' on Kor Da — verified short stay in Islamabad!';
    if (navigator.share) {
      navigator.share({ title: title, text: text, url: url }).catch(function() {});
    } else {
      var popup = document.getElementById('sharePopup');
      if (!popup) {
        popup = document.createElement('div');
        popup.id = 'sharePopup';
        popup.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#fff;border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,.18);padding:14px 18px;display:flex;gap:10px;z-index:9999;align-items:center;animation:slideUp .25s ease';
        popup.innerHTML = '<span style="font-size:.78rem;font-weight:700;color:var(--i3);margin-right:4px">Share:</span>'
          + '<a href="https://wa.me/?text=' + encodeURIComponent(text + ' ' + url) + '" target="_blank" rel="noopener" style="width:38px;height:38px;border-radius:10px;background:#25D366;color:#fff;display:flex;align-items:center;justify-content:center;font-size:1.1rem;text-decoration:none" title="WhatsApp">&#128172;</a>'
          + '<a href="https://www.facebook.com/sharer/sharer.php?u=' + encodeURIComponent(url) + '" target="_blank" rel="noopener" style="width:38px;height:38px;border-radius:10px;background:#1877F2;color:#fff;display:flex;align-items:center;justify-content:center;font-size:1.1rem;text-decoration:none" title="Facebook">f</a>'
          + '<a href="https://twitter.com/intent/tweet?text=' + encodeURIComponent(text) + '&url=' + encodeURIComponent(url) + '" target="_blank" rel="noopener" style="width:38px;height:38px;border-radius:10px;background:#1DA1F2;color:#fff;display:flex;align-items:center;justify-content:center;font-size:1.1rem;text-decoration:none" title="Twitter">&#128038;</a>'
          + '<button onclick="navigator.clipboard.writeText(\'' + url.replace(/'/g, "\\'") + '\');this.innerHTML=\'&#10003;\';setTimeout(function(){document.getElementById(\'sharePopup\')?.remove()},1200)" style="width:38px;height:38px;border-radius:10px;background:var(--s);border:1px solid rgba(28,77,64,.12);color:var(--i3);display:flex;align-items:center;justify-content:center;font-size:1rem;cursor:pointer" title="Copy link">&#128279;</button>'
          + '<button onclick="this.parentElement.remove()" style="width:28px;height:28px;border-radius:50%;background:var(--s);border:none;color:var(--i4);font-size:.9rem;cursor:pointer;flex-shrink:0" aria-label="Close">&times;</button>';
        document.body.appendChild(popup);
        setTimeout(function() { var el = document.getElementById('sharePopup'); if (el) el.remove(); }, 6000);
      }
    }
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
