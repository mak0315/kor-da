/**
 * KOR DA — NAVIGATION JS (navigation.js)
 * Sticky header scroll behavior & mobile drawer controls
 */
(function(){
  'use strict';
  window.addEventListener('DOMContentLoaded', function(){
    var nav = document.querySelector('#nav') || document.querySelector('header nav');
    if (nav) {
      window.addEventListener('scroll', function(){
        nav.classList.toggle('sc', window.scrollY > 60);
      }, { passive: true });
    }

    var nhbg = document.getElementById('nhbg'),
        ndr  = document.getElementById('ndr'),
        novl = document.getElementById('novl'),
        ndx  = document.getElementById('ndx');

    function openD(){
      if(nhbg) nhbg.classList.add('open');
      if(ndr) ndr.classList.add('open');
      if(novl) novl.classList.add('on');
      if(nhbg) nhbg.setAttribute('aria-expanded','true');
      document.body.style.overflow = 'hidden';
    }

    function closeD(){
      if(nhbg) nhbg.classList.remove('open');
      if(ndr) ndr.classList.remove('open');
      if(novl) novl.classList.remove('on');
      if(nhbg) nhbg.setAttribute('aria-expanded','false');
      document.body.style.overflow = '';
    }

    if(nhbg) {
      nhbg.addEventListener('click', function(){
        ndr && ndr.classList.contains('open') ? closeD() : openD();
      });
    }
    if(ndx) ndx.addEventListener('click', closeD);
    if(novl) novl.addEventListener('click', closeD);

    var ndls = document.querySelectorAll('.ndl');
    for(var i = 0; i < ndls.length; i++){
      ndls[i].addEventListener('click', closeD);
    }

    /* ── Mobile bottom nav ─────────────────────────────── */
    var mnav   = document.getElementById('mnav'),
        mItems = mnav ? mnav.querySelectorAll('.mnav-i[data-sec]') : [],
        mMenu  = document.getElementById('mnavMenuBtn'),
        mSheet = document.getElementById('msheet'),
        mOv    = document.getElementById('moverlay'),
        mX     = document.getElementById('msheetX');

    function setMNav(id){
      for(var i = 0; i < mItems.length; i++){
        var on = mItems[i].getAttribute('data-sec') === id;
        mItems[i].classList.toggle('on', on);
        if(on) mItems[i].setAttribute('aria-current', 'page');
        else mItems[i].removeAttribute('aria-current');
      }
    }

    for(var j = 0; j < mItems.length; j++){
      (function(el){
        el.addEventListener('click', function(){
          setMNav(el.getAttribute('data-sec'));
        });
      })(mItems[j]);
    }

    /* Scroll spy: highlight Explore / Host / About by section */
    var spySecs = [['hero', null], ['host-form', null], ['about', null]];
    for(var s = 0; s < spySecs.length; s++){
      var se = document.getElementById(spySecs[s][0]);
      spySecs[s][1] = se;
    }
    function spyScroll(){
      var y = window.scrollY + 110, cur = 'hero';
      for(var s = 0; s < spySecs.length; s++){
        if(spySecs[s][1] && spySecs[s][1].offsetTop <= y) cur = spySecs[s][0];
      }
      setMNav(cur);
    }
    window.addEventListener('scroll', spyScroll, { passive: true });
    spyScroll();

    /* ── Menu bottom sheet ─────────────────────────────── */
    function openSheet(){
      if(!mSheet) return;
      mSheet.classList.add('open');
      mOv && mOv.classList.add('on');
      if(mMenu){ mMenu.setAttribute('aria-expanded', 'true'); mMenu._f = document.activeElement; }
      if(mOv) mOv.setAttribute('aria-hidden', 'false');
      document.body.style.overflow = 'hidden';
      var first = mSheet.querySelector('.msi, .msheet-x');
      first && first.focus();
    }

    function closeSheet(){
      if(!mSheet) return;
      mSheet.classList.remove('open');
      mOv && mOv.classList.remove('on');
      if(mMenu) mMenu.setAttribute('aria-expanded', 'false');
      mOv && mOv.setAttribute('aria-hidden', 'true');
      document.body.style.overflow = '';
      if(mMenu && mMenu._f) mMenu.focus();
    }

    if(mMenu) mMenu.addEventListener('click', function(){
      mSheet && mSheet.classList.contains('open') ? closeSheet() : openSheet();
    });
    if(mX) mX.addEventListener('click', closeSheet);
    if(mOv) mOv.addEventListener('click', closeSheet);

    var msiLinks = mSheet ? mSheet.querySelectorAll('.msi') : [];
    for(var k = 0; k < msiLinks.length; k++){
      msiLinks[k].addEventListener('click', closeSheet);
    }

    document.addEventListener('keydown', function(e){
      if(e.key === 'Escape' && mSheet && mSheet.classList.contains('open')) closeSheet();
    });
  });
})();
