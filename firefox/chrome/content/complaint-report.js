let $ = function(id) {
  return document.getElementById(id);
};

let cmdCheckbox = function() {
  const dialog = $('adban-complaint-dialog');
  if ($('adban-complaint-checkbox').checked) {
    dialog.removeAttribute('buttondisabledaccept');
  }
  else {
    dialog.setAttribute('buttondisabledaccept', 'true');
  }
};

let complaint_callback = window.arguments[0];

let cmdDialogAccept = function() {
  complaint_callback($('adban-complaint-site-url').value, $('adban-complaint-comment').value);
};

let init = function() {
  $('adban-complaint-site-url').value = window.arguments[1];

  $('adban-complaint-checkbox').addEventListener('command', cmdCheckbox, false);
  $('adban-complaint-dialog').addEventListener('dialogaccept', cmdDialogAccept, false);

  window.addEventListener('unload', shutdown, false);
};

let shutdown = function() {
  $('adban-complaint-checkbox').removeEventListener('command', cmdCheckbox, false);
  $('adban-complaint-dialog').removeEventListener('dialogaccept', cmdDialogAccept, false);

  window.removeEventListener('load', init, false);
  window.removeEventListener('unload', shutdown, false);
};

window.addEventListener('load', init, false);

