/**
 * KOR DA — APP ENTRY POINT (app.js)
 * Light orchestrator: calculator, area filter, category delegation, lazy loading
 * All modules loaded via <script> tags in order.
 */
'use strict';

/* Listing filtering routes to search.js (window.fCat / window.gFilter) */
function fCat(btn){ if (window.fCat) window.fCat(btn); }
function gFilter(cat){ if (window.gFilter) window.gFilter(cat); }

/* Area Filter */
function aArea(btn, area){
  if(btn){
    var atags = $$('.atag');
    for(var i = 0; i < atags.length; i++) atags[i].classList.remove('on');
    btn.classList.add('on');
  }
  if(area && window.PropertyService){
    var hc = $('hCity');
    if(hc){
      for(var i = 0; i < hc.options.length; i++){
        if(hc.options[i].value && hc.options[i].value.toLowerCase().indexOf(area.toLowerCase()) >= 0){
          hc.value = hc.options[i].value; break;
        }
      }
    }
    window.PropertyService.search({ area: area }).then(function(results){
      if (window.renderListings) window.renderListings(results);
    });
  }
  var el = $('listings'); if(el) el.scrollIntoView({ behavior:'smooth', block:'start' });
}

/* Lazy Image Loading */
if('IntersectionObserver' in window){
  window.addEventListener('DOMContentLoaded', function(){
    var imgObs = new IntersectionObserver(function(e){
      for(var i = 0; i < e.length; i++){
        if(e[i].isIntersecting){
          var img = e[i].target;
          if(img.dataset.src){ img.src = img.dataset.src; delete img.dataset.src; }
          imgObs.unobserve(img);
        }
      }
    }, { rootMargin:'200px 0px' });
    var lazyImgs = document.querySelectorAll('img[loading="lazy"]');
    for(var i = 0; i < lazyImgs.length; i++) imgObs.observe(lazyImgs[i]);
  });
}

console.log('%cKor Da — Static MVP v2.0','background:#1C4D40;color:#fff;padding:8px 16px;border-radius:6px;font-weight:700');
console.log('%c0315-5881733 | kordapakistan@gmail.com | @korda.pk','color:#1C4D40;font-size:11px');

/* Open property from shared hash link: #property=slug */
function checkPropertyHash() {
  var h = window.location.hash;
  if (h && h.indexOf('#property=') === 0) {
    var slug = decodeURIComponent(h.substring(10));
    if (slug && window.showPropertyDetail) {
      setTimeout(function() { window.showPropertyDetail(slug); }, 400);
    }
  }
}
window.addEventListener('DOMContentLoaded', checkPropertyHash);
window.addEventListener('hashchange', function() { if (window.location.hash.indexOf('#property=') === 0) checkPropertyHash(); });
