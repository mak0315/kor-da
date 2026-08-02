/**
 * KOR DA — PWA INSTALL PROMPT (install.js)
 * Shows a non-blocking install card / bottom sheet when the app is installable,
 * an iOS "Add to Home Screen" guide on iPhone/iPad, then never nags again.
 * Depends on utils.js (toast).
 */
'use strict';

(function(){
  var DELAY_MS = 9000;        // show after ~9s
  var SCROLL_RATIO = 0.28;    // or after 28% scroll
  var RETRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
  var LS_DISMISS = 'korda_install_dismissed';
  var LS_INSTALLED = 'korda_installed';

  var deferred = null;
  var successShown = false;
  var scheduled = false;

  function isiOS(){
    return /iphone|ipad|ipod/i.test(navigator.userAgent) ||
      (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  }
  function isStandalone(){
    try {
      return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
        window.navigator.standalone === true;
    } catch(e){ return false; }
  }
  function dismissedRecently(){
    try {
      var ts = +localStorage.getItem(LS_DISMISS);
      return !!ts && (Date.now() - ts) < RETRY_MS;
    } catch(e){ return false; }
  }
  function installed(){
    try { return !!localStorage.getItem(LS_INSTALLED); } catch(e){ return false; }
  }
  function rememberDismissal(){
    try { localStorage.setItem(LS_DISMISS, String(Date.now())); } catch(e){}
  }
  function rememberInstalled(){
    try { localStorage.setItem(LS_INSTALLED, '1'); } catch(e){}
  }

  function success(){
    if(successShown) return;
    successShown = true;
    hide();
    rememberInstalled();
    if(typeof toast === 'function') toast('Kor Da has been installed successfully.');
  }

  var el, xBtn, laterBtn, installBtn, iosLater, viewInstall, viewIos;

  function show(){
    if(!el) return;
    if(installed() || dismissedRecently() || isStandalone()) return;
    el.classList.add('show');
    el.setAttribute('aria-hidden', 'false');
    var focusable = el.querySelector('button:not(.aip-x)');
    if(focusable) focusable.focus();
  }
  function hide(){
    if(!el) return;
    el.classList.remove('show');
    el.setAttribute('aria-hidden', 'true');
  }
  function dismiss(){
    hide();
    rememberDismissal();
  }

  function schedule(){
    if(scheduled) return;
    scheduled = true;
    var timer = setTimeout(function(){ show(); }, DELAY_MS);
    window.addEventListener('scroll', function onSc(){
      var doc = document.documentElement;
      var max = Math.max(1, doc.scrollHeight - window.innerHeight);
      if(max && window.scrollY / max >= SCROLL_RATIO){
        clearTimeout(timer);
        window.removeEventListener('scroll', onSc);
        show();
      }
    }, { passive: true });
  }

  function chooseView(ios){
    if(!viewInstall || !viewIos) return;
    if(ios){ viewIos.removeAttribute('hidden'); viewInstall.setAttribute('hidden', ''); }
    else { viewInstall.removeAttribute('hidden'); viewIos.setAttribute('hidden', ''); }
  }

  function init(){
    el = document.getElementById('aip');
    if(!el) return;

    xBtn      = document.getElementById('aipX');
    laterBtn  = document.getElementById('aipLater');
    installBtn= document.getElementById('aipInstall');
    iosLater  = document.getElementById('aipLater2');
    viewInstall = document.getElementById('aipInstallView');
    viewIos     = document.getElementById('aipIosView');

    if(xBtn) xBtn.addEventListener('click', dismiss);
    if(laterBtn) laterBtn.addEventListener('click', dismiss);
    if(iosLater) iosLater.addEventListener('click', dismiss);

    if(installBtn) installBtn.addEventListener('click', function(){
      if(deferred){
        var p = deferred;
        deferred = null;
        p.prompt();
        p.userChoice.then(function(choice){
          if(choice.outcome === 'accepted') success();
          else dismiss();
        });
      } else {
        dismiss();
      }
    });

    document.addEventListener('keydown', function(e){
      if(e.key === 'Escape') hide();
    });

    /* iOS Safari: no native prompt, show the Add-to-Home-Screen guide. */
    if(isiOS()){
      chooseView(true);
      schedule();
      return;
    }

    /* Android / desktop Chromium: wait for beforeinstallprompt. */
    chooseView(false);
  }

  window.addEventListener('beforeinstallprompt', function(e){
    e.preventDefault();
    deferred = e;
    if(installed() || dismissedRecently() || isStandalone()) return;
    chooseView(false);
    schedule();
  });

  window.addEventListener('appinstalled', function(){
    success();
  });

  document.addEventListener('DOMContentLoaded', init);

  /* Register service worker (root scope, covers whole site). */
  if('serviceWorker' in navigator){
    window.addEventListener('load', function(){
      navigator.serviceWorker.register('/sw.js').catch(function(){});
    });
  }
})();
