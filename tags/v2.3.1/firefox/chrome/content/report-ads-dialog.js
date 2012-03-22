// Use strict mode. https://developer.mozilla.org/en/JavaScript/Strict_mode .
"use strict";

// use this scoping hack in order to hide objects defined inside the anonymous function
// from the global scope.
(function() {
  const $ = function(id) {
    return document.getElementById(id);
  };

  const complaint_callback = window.arguments[0];

  const cmdDialogAccept = function() {
    complaint_callback($('adban-complaint-site-url').value, $('adban-complaint-comment').value);
  };

  const init = function() {
    window.removeEventListener('load', init, false);

    $('adban-complaint-site-url').value = window.arguments[1];
    $('adban-complaint-dialog').addEventListener('dialogaccept', cmdDialogAccept, false);
    window.addEventListener('unload', shutdown, false);
  };

  const shutdown = function() {
    $('adban-complaint-dialog').removeEventListener('dialogaccept', cmdDialogAccept, false);
    window.removeEventListener('load', init, false);
    window.removeEventListener('unload', shutdown, false);
  };

  window.addEventListener('load', init, false);
})();

