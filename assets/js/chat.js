/**
 * KOR DA — CHAT WIDGET (chat.js)
 * Floating chat button, tab switching, auto-reply, message input
 */
'use strict';

(function(){
  var cOpen = false;
  var AR = [
    {k:['easypais','jazzcash','pay','payment'],r:'We accept EasyPaisa, JazzCash, debit/credit card, and bank transfer — all in PKR. Call/WhatsApp: 0315-5881733'},
    {k:['book','booking','reserve','available'],r:'WhatsApp us at 0315-5881733 with the property name and dates. We respond within 2 hours!'},
    {k:['cnic','nadra','verify'],r:'Every host is verified via NADRA Verisys before listing. Only CNIC-verified Pakistanis can host on Kor Da.'},
    {k:['hello','hi','salam','aoa','assalam'],r:'Wa Alaikum Assalam! Welcome to Kor Da Islamabad. Looking for a stay or want to list your property?'},
    {k:['commission','fee','percent'],r:'Kor Da charges a small commission only on completed bookings — hosts keep the majority. Zero listing fee, zero monthly cost.'},
    {k:['f-7','f-8','dha','bahria','g-8','islamabad','pims','nust'],r:'We cover all of Islamabad: F-6 to F-11, G-6 to G-15, DHA, Bahria Town, Blue Area, Bani Gala and all sectors.'},
    {k:['safe','trust','secure','escrow'],r:'CNIC-verified hosts. 24-hour dispute protection. WhatsApp: 0315-5881733 for any issue.'},
    {k:['cancel','refund'],r:'Contact us within 24 hours of check-in via WhatsApp: 0315-5881733. We respond same day.'}
  ];

  window.tChat = function(){
    var cpanel = $('cpanel'), cfab = $('cfab'), cbadge = $('cbadge');
    cOpen = !cOpen;
    if(cpanel) cpanel.classList.toggle('open', cOpen);
    if(cfab) cfab.setAttribute('aria-expanded', String(cOpen));
    if(cOpen && cbadge) cbadge.style.opacity = '0';
  };

  window.sCTab = function(btn){
    var tabs = $$('.ctab');
    for(var i = 0; i < tabs.length; i++) tabs[i].classList.remove('on');
    btn.classList.add('on');
    var panes = $$('.cpane');
    for(var i = 0; i < panes.length; i++) panes[i].classList.remove('on');
    var pane = $('pt-' + btn.dataset.tab);
    if(pane) pane.classList.add('on');
  };

  function addMsg(c, t, type){
    var d = document.createElement('div');
    d.className = 'cmsg ' + type;
    d.textContent = t;
    c.appendChild(d);
    c.scrollTop = c.scrollHeight;
  }

  window.sChat = function(){
    var inp = $('cin'), ml = $('cml');
    var text = inp ? inp.value.trim() : '';
    if(!text) return;
    addMsg(ml, text, 'out');
    inp.value = '';
    var low = text.toLowerCase();
    var match = null;
    for(var i = 0; i < AR.length; i++){
      for(var j = 0; j < AR[i].k.length; j++){
        if(low.indexOf(AR[i].k[j]) >= 0){ match = AR[i]; break; }
      }
      if(match) break;
    }
    var reply = match ? match.r : 'For fastest help WhatsApp us at 0315-5881733 — we reply in minutes!';
    setTimeout(function(){ addMsg(ml, reply, 'in'); }, 900);
  };

  window.addEventListener('DOMContentLoaded', function(){
    var cpanel = $('cpanel'), cfab = $('cfab'), cbadge = $('cbadge');
    if(cbadge) setTimeout(function(){ cbadge.style.opacity = '0'; }, 3200);

    document.addEventListener('click', function(e){
      if(cOpen && cpanel && cfab && !cpanel.contains(e.target) && !cfab.contains(e.target)){
        cOpen = false;
        cpanel.classList.remove('open');
        cfab.setAttribute('aria-expanded','false');
      }
    });

    var cinEl = $('cin');
    if(cinEl) cinEl.addEventListener('keypress', function(e){ if(e.key === 'Enter') window.sChat(); });
  });
})();
