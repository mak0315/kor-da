/**
 * KOR DA — UTILITIES (utils.js)
 * Global helpers: $, $$, fmt, toast
 * Must load BEFORE all other modules.
 */
'use strict';

var $ = function(id){ return document.getElementById(id); };
var $$ = function(s){ return document.querySelectorAll(s); };
function fmt(n){ return parseInt(n).toLocaleString('en-PK'); }

function toast(msg, type, dur){
  type = type || 'ok'; dur = dur || 3400;
  var el = $('toast');
  if(!el) return;
  var icons = { ok:'✓', warn:'⚠', err:'✗', info:'ℹ' };
  el.innerHTML = '<span>' + (icons[type] || '✓') + '</span> ' + msg;
  el.className = 'on ' + type;
  clearTimeout(el._t);
  el._t = setTimeout(function(){ el.classList.remove('on'); }, dur);
}
