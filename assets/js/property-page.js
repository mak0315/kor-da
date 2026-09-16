/**
 * KOR DA — REUSABLE PROPERTY PAGE (property-page.js)
 *
 * Shared controller for /properties/<slug>.html pages.
 *
 * Architecture:
 *   Shared shell (navbar + mobile nav + footer)  -> assets/js/shell.js
 *   + Property data (PropertyService / content/compiled/properties.json)
 *   + Reusable property template (rendered below)
 *
 * The slug is derived from the page URL (/properties/<slug>.html), then the
 * matching property is loaded through PropertyService. Rendering reuses the
 * exact markup and CSS that the original static property pages used — this is
 * an architecture/refactoring migration, not a redesign.
 */
(function(){
  'use strict';

  var CONFIG = window.KORDA_CONFIG || {
    phoneDisplay: '0315-5881733',
    waNumber: '923155881733',
    siteName: 'Kor Da',
    siteUrl: 'https://www.kordaa.com'
  };

  /* The existing "More Properties in Islamabad" section (verbatim from the
     original property pages). */
  var AREA_LINKS = [
    { href: '/area/f-7-islamabad',    label: 'F-7 Islamabad' },
    { href: '/area/f-11-islamabad',   label: 'F-11 Islamabad' },
    { href: '/area/g-11-islamabad',   label: 'G-11 Islamabad' },
    { href: '/area/e-11-islamabad',   label: 'E-11 (Near NUST)' },
    { href: '/area/blue-area-islamabad', label: 'Blue Area' },
    { href: '/area/dha-islamabad',    label: 'DHA Islamabad' }
  ];

  function esc(s) {
    return String(s == null ? '' : s).replace(/[<>&"']/g, function(c) {
      return { '<':'&lt;', '>':'&gt;', '&':'&amp;', '"':'&quot;', "'":'&#39;' }[c];
    });
  }

  function fmt(n) { return parseInt(n, 10).toLocaleString('en-PK'); }

  /* ── ROUTING ─────────────────────────────────────────────────────────── */

  function slugFromPath() {
    var path = window.location.pathname.replace(/\/+$/, '');
    var parts = path.split('/');
    var file = parts[parts.length - 1] || '';
    if (!file || file === 'index.html') return '';
    return file.replace(/\.html$/i, '');
  }

  /* ── SHARED SHELL ──────────────────────────────────────────────────────
     The navbar, drawer, mobile nav, profile sheet and footer are rendered
     by assets/js/shell.js (window.KorDaShell) — the single source of truth
     for the site chrome. This module only renders property content into
     #pp-root. Property shells must load shell.js (before this file) and
     navigation.js (after this file).
  ─────────────────────────────────────────────────────────────────────── */

  /* ── TEMPLATE: HERO / GALLERY LEAD ───────────────────────────────────── */

  function renderHero(prop) {
    var img = prop.image || (Array.isArray(prop.gallery) && prop.gallery[0]) || '';
    var bgStyle = img
      ? ' style="background-image:url(\'' + img.replace(/'/g, "\\'") + '\')"'
      : ' style="background-image:linear-gradient(135deg,var(--t1),var(--t0))"';
    var loc = prop.address || prop.city || prop.area || 'Islamabad';
    return '<div class="pd-hero">' +
             '<div class="pd-hero-bg"' + bgStyle + '></div>' +
             '<div class="pd-hero-con">' +
               '<h1>' + esc(prop.title || prop.type) + '</h1>' +
               '<div class="pd-loc">&#128205; ' + esc(loc) + '</div>' +
             '</div>' +
           '</div>';
  }

  /* ── TEMPLATE: DESCRIPTION ───────────────────────────────────────────── */

  function renderDescription(prop) {
    var raw = prop.body || prop.description || '';
    var paras = String(raw).split(/\n+/).map(function(t) { return t.trim(); }).filter(Boolean);
    if (!paras.length) paras = ['A comfortable, verified stay in Islamabad.'];
    return paras.map(function(p) { return '<p>' + esc(p) + '</p>'; }).join('\n');
  }

  /* ── TEMPLATE: AMENITIES ─────────────────────────────────────────────── */

  function renderAmenities(prop) {
    var list = (Array.isArray(prop.amenities) && prop.amenities.length)
      ? prop.amenities
      : ['WiFi', 'AC', 'Kitchen'];
    return list.map(function(a) { return '<span>' + esc(a) + '</span>'; }).join('');
  }

  /* ── TEMPLATE: NEARBY LANDMARKS (data-driven; hidden when absent) ────── */

  function renderLandmarks(prop) {
    var list = prop.landmarks;
    if (!Array.isArray(list) || !list.length) return '';
    return '<h3 class="t-h3" style="margin:20px 0 10px">Nearby Landmarks</h3>' +
           '<ul style="font-size:.92rem;color:var(--i3);line-height:2;padding-left:16px">' +
           list.map(function(x) { return '<li>' + esc(x) + '</li>'; }).join('') +
           '</ul>';
  }

  /* ── TEMPLATE: BOOKING / PRICE BOX (WhatsApp flow) ───────────────────── */

  function renderBooking(prop) {
    return '<div class="pd-price-box">' +
             '<div class="pd-price">PKR ' + fmt(prop.price) + ' <span>/ night</span></div>' +
             '<div class="pd-meta">' +
               '<div class="pd-meta-item"><div class="label">Beds</div><div class="value">' + esc(prop.beds || '1') + '</div></div>' +
               '<div class="pd-meta-item"><div class="label">Baths</div><div class="value">' + esc(prop.baths || 1) + '</div></div>' +
               '<div class="pd-meta-item"><div class="label">Max Guests</div><div class="value">' + esc(prop.maxGuests || 2) + '</div></div>' +
               '<div class="pd-meta-item"><div class="label">Type</div><div class="value">' + esc(prop.type || 'Stay') + '</div></div>' +
             '</div>' +
             '<a href="/checkout?property=' + encodeURIComponent(prop.slug || prop.id || '') + '" class="btn btn-p" style="width:100%;justify-content:center;margin-top:16px">Book Now</a>' +
             '<p style="font-size:.75rem;color:var(--i5);text-align:center;margin-top:10px">CNIC-verified host | Secure payments | Pay in PKR via EasyPaisa</p>' +
           '</div>';
  }

  /* ── TEMPLATE: PROPERTY INFORMATION COLUMN ───────────────────────────── */

  function renderInformation(prop) {
    return '<section class="sec">' +
             '<div class="wrap pd-body">' +
               '<div class="pd-desc">' +
                 renderDescription(prop) +
                 '<h3 class="t-h3" style="margin:20px 0 10px">Amenities</h3>' +
                 '<div class="pd-amenities">' + renderAmenities(prop) + '</div>' +
                 renderLandmarks(prop) +
               '</div>' +
               '<div class="pd-side">' + renderBooking(prop) + '</div>' +
             '</div>' +
           '</section>';
  }

  /* ── TEMPLATE: RELATED PROPERTIES (existing area section) ────────────── */

  function renderRelated() {
    var btns = AREA_LINKS.map(function(a) {
      return '<a href="' + a.href + '" class="btn btn-o">' + esc(a.label) + '</a>';
    }).join('');
    return '<section class="sec bg-cream">' +
             '<div class="wrap" style="text-align:center">' +
               '<h2 class="t-h2" style="margin-bottom:12px">More Properties in Islamabad</h2>' +
               '<p class="lg-t" style="margin-bottom:24px">Explore other verified stays across all Islamabad sectors.</p>' +
               '<div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">' + btns + '</div>' +
             '</div>' +
           '</section>';
  }

  /* ── NOT-FOUND STATE (invalid slug / missing / unpublished) ──────────── */

  function renderNotFound() {
    if (document.title === CONFIG.siteName || !document.title) {
      document.title = 'Property not found | ' + CONFIG.siteName;
    }
    return '<div class="pd-hero">' +
             '<div class="pd-hero-bg" style="background-image:linear-gradient(135deg,var(--t1),var(--t0))"></div>' +
             '<div class="pd-hero-con">' +
               '<h1>Property not found</h1>' +
               '<div class="pd-loc">The property you&#39;re looking for is no longer available.</div>' +
             '</div>' +
           '</div>' +
           '<section class="sec">' +
             '<div class="wrap" style="text-align:center">' +
               '<h2 class="t-h2" style="margin-bottom:12px">Explore other verified stays</h2>' +
               '<p class="lg-t" style="margin-bottom:24px">Find a comfortable, verified stay across all Islamabad sectors.</p>' +
               '<div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">' +
                 '<a href="/#listings" class="btn btn-p">Explore Stays</a>' +
               '</div>' +
             '</div>' +
           '</section>' +
           renderRelated();
  }

  /* ── SEO (fill only missing tags; static per-page head wins) ─────────── */

  function setMeta(attr, name, content) {
    var sel = 'meta[' + attr + '="' + name + '"]';
    var el = document.querySelector(sel);
    if (!el) {
      el = document.createElement('meta');
      el.setAttribute(attr, name);
      document.head.appendChild(el);
    }
    if (!el.getAttribute('content')) el.setAttribute('content', content);
  }

  function setLinkCanonical(href) {
    var el = document.querySelector('link[rel="canonical"]');
    if (!el) {
      el = document.createElement('link');
      el.setAttribute('rel', 'canonical');
      document.head.appendChild(el);
    }
    if (!el.getAttribute('href')) el.setAttribute('href', href);
  }

  function applySEO(prop) {
    if (!prop) return;
    var slug = prop.slug || prop.id || slugFromPath();
    var base = (CONFIG.siteUrl || 'https://www.kordaa.com').replace(/\/+$/, '');
    var title = prop.seoTitle || ((prop.title || prop.type) + ' | ' + CONFIG.siteName);
    var desc = prop.seoDescription || ((prop.title || prop.type) + ' on ' + CONFIG.siteName +
      '. PKR ' + fmt(prop.price) + '/night in ' + (prop.city || 'Islamabad') +
      '. Verified host. WhatsApp ' + CONFIG.phoneDisplay + '.');
    var canon = base + '/properties/' + slug;

    if (!document.title) document.title = title;
    setMeta('name', 'description', desc);
    setMeta('property', 'og:title', title);
    setMeta('property', 'og:description', desc);
    setMeta('property', 'og:url', canon);
    setLinkCanonical(canon);
  }

  /* ── INIT ────────────────────────────────────────────────────────────── */

  function init() {
    var root = document.getElementById('pp-root');
    if (!root) return;

    var slug = slugFromPath();
    if (!slug) { root.innerHTML = renderNotFound(); return; }

    if (!window.PropertyService) { root.innerHTML = renderNotFound(); return; }

    PropertyService.getBySlug(slug).then(function(prop) {
      if (!prop) { root.innerHTML = renderNotFound(); return; }
      applySEO(prop);
      root.innerHTML = renderHero(prop) + renderInformation(prop) + renderRelated();
    }).catch(function() {
      root.innerHTML = renderNotFound();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
