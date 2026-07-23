/**
 * KOR DA — WHATSAPP INTEGRATION (whatsapp.js)
 * Form handlers live in forms.js (loaded separately).
 * Hero search is handled by search.js (window.doSearch).
 * This file only provides the openWA fallback helper.
 */
'use strict';

/* openWA is already defined in forms.js.
   This file is a no-op placeholder for backwards compatibility.
   If forms.js hasn't loaded yet, provide a fallback. */
if(typeof window.openWA !== 'function'){
  window.openWA = function(msg){
    var wa = (window.KORDA_CONFIG && window.KORDA_CONFIG.waNumber) ? window.KORDA_CONFIG.waNumber : '923155881733';
    window.open('https://wa.me/' + wa + '?text=' + encodeURIComponent(msg), '_blank', 'noopener');
  };
}
