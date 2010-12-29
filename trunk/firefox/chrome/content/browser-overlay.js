let Cc = Components.classes;
let Ci = Components.interfaces;

let prompts = Cc['@mozilla.org/embedcomp/prompt-service;1'].getService(Ci.nsIPromptService);
let adban = Cc['@ad-ban.appspot.com/adban;1'].getService().wrappedJSObject;

let $ = function(id) {
  return document.getElementById(id);
};

let _ = function(id, params) {
  const adban_strings = $('adban-strings');
  if (params) {
    return adban_strings.getFormattedString(id, params);
  }
  return adban_strings.getString(id);
};

let alert_states = {};

let conditionalAlert = function(alert_name, msg) {
  let alert_state = alert_states[alert_name];
  if (!alert_state) {
    alert_state = alert_states[alert_name] = { value: false };
  }
  if (!alert_state.value) {
    prompts.alertCheck(window, 'AdBan', msg, _('dont-show-this-message-again'), alert_state);
  }
};

let openTab = function(url) {
  gBrowser.selectedTab = gBrowser.addTab(url);
};

let firstRun = function() {
  // add adban button to the main toolbar.
  const nav_bar = $('nav-bar');
  const current_set = nav_bar.currentSet;
  if (current_set.indexOf('adban-button') == -1) {
    // nav_bar.insertItem() doesn't work as expected.
    // the following code snippet was borrowed from
    // https://developer.mozilla.org/en/Code_snippets/Toolbar#Adding_button_by_default
    current_set += ',adban-button';
    nav_bar.currentSet = current_set;
    nav_bar.setAttribute('currentset', current_set);
    document.persist(nav_bar.id, 'currentset');
  }

  // open the help page for the extension.
  openTab(adban.FIRST_RUN_URL);
};

let stateToggle = function(from, to) {
  to.setAttribute('disabled', 'true');
  from.removeAttribute('disabled');
};

let onStateChange = function(is_active) {
  const cmd_adban_stop = $('cmd-adban-stop');
  const cmd_adban_start = $('cmd-adban-start');
  const adban_button = $('adban-button');
  if (is_active) {
    stateToggle(cmd_adban_stop, cmd_adban_start);
    adban_button.label = 'AdBan: ' + _('on');
  }
  else {
    stateToggle(cmd_adban_start, cmd_adban_stop);
    adban_button.label = 'AdBan: ' + _('off');
  }
};

let cmdStop = function() {
  adban.stop();
  conditionalAlert('adban-stopped', _('adban-stopped'));
};

let cmdStart = function() {
  adban.start();
};

let cmdComplaint = function() {
  const complaint_callback = function(site_url, comment) {
    const success_callback = function() {
      conditionalAlert('complaint-sent', _('complaint-sent', [site_url]));
    };
    adban.sendUrlComplaint(site_url, comment, success_callback);
  };
  const initial_site_url = gBrowser.currentURI.spec;
  // const initial_site_url = $('urlbar').value;
  const complaint_window = window.openDialog('chrome://adban/content/complaint-report.xul',
      'adban-complaint-window', '', complaint_callback, initial_site_url);
  complaint_window.focus();
};

let cmdHelp = function() {
  openTab(adban.HELP_URL);
};

let state_listener_id;

let init = function() {
  const extension = Application.extensions.get('adban@ad-ban.appspot.com');
  if (extension.firstRun) {
    firstRun();
  }

  $('cmd-adban-stop').addEventListener('command', cmdStop, false);
  $('cmd-adban-start').addEventListener('command', cmdStart, false);
  $('cmd-adban-complaint').addEventListener('command', cmdComplaint, false);
  $('cmd-adban-help').addEventListener('command', cmdHelp, false);

  // DOMFrameContentLoaded doesn't work as expected,
  // while DOMContentLoaded catches iframes and frames.
  // see https://developer.mozilla.org/en/Gecko-Specific_DOM_Events .
  gBrowser.addEventListener('DOMContentLoaded', adban, true);
  state_listener_id = adban.subscribeToStateChange(onStateChange);

  window.addEventListener('unload', shutdown, false);
};

let shutdown = function() {
  adban.unsubscribeFromStateChange(state_listener_id);
  gBrowser.removeEventListener('DOMContentLoaded', adban, true);

  $('cmd-adban-stop').removeEventListener('command', cmdStop, false);
  $('cmd-adban-start').removeEventListener('command', cmdStart, false);
  $('cmd-adban-complaint').removeEventListener('command', cmdComplaint, false);
  $('cmd-adban-help').removeEventListener('command', cmdHelp, false);

  window.removeEventListener('load', init, false);
  window.removeEventListener('unload', shutdown, false);
};

window.addEventListener('load', init, false);

