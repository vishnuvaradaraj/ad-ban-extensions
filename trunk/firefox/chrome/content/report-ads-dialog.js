// use this scoping hack in order to hide objects defined inside the branch
// with the 'let' statement from the global scope.
(function() {
  let $ = function(id) {
    return document.getElementById(id);
  };

  let complaint_callback = window.arguments[0];

  let cmdDialogAccept = function() {
    complaint_callback($('adban-complaint-site-url').value, $('adban-complaint-comment').value);
  };

  let init = function() {
    $('adban-complaint-site-url').value = window.arguments[1];
    $('adban-complaint-dialog').addEventListener('dialogaccept', cmdDialogAccept, false);
    window.addEventListener('unload', shutdown, false);
  };

  let shutdown = function() {
    $('adban-complaint-dialog').removeEventListener('dialogaccept', cmdDialogAccept, false);
    window.removeEventListener('load', init, false);
    window.removeEventListener('unload', shutdown, false);
  };

  window.addEventListener('load', init, false);
})();

