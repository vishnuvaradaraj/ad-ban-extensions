let Cc = Components.classes;
let Ci = Components.interfaces;

let prompts = Cc['@mozilla.org/embedcomp/prompt-service;1'].getService(Ci.nsIPromptService);
let adban = Cc['@ad-ban.appspot.com/adban;1'].getService().wrappedJSObject;
let logging = adban.logging;
let pref_branch = adban.pref_branch;

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

let conditionalAlert = function(alert_name, msg) {
  alert_name = 'alert-states.' + alert_name;
  if (pref_branch.prefHasUserValue(alert_name) &&
      pref_branch.getBoolPref(alert_name)) {
    logging.info('the alert [%s] is disabled in preferences', alert_name);
    return;
  }
  const state_obj = {
      value: false,
  };
  prompts.alertCheck(window, 'AdBan', msg, _('dont-show-this-message-again'), state_obj);
  if (state_obj.value) {
    logging.info('disabling the alert [%s] in preferences', alert_name);
    pref_branch.setBoolPref(alert_name, true);
  }
};

let openTab = function(url) {
  logging.info('opening the tab with url=[%s]', url);
  // use this hack, otherwise firefox 3.6 can skip the tab
  // if another tab is immediately opened after this tab.
  const open_tab_callback = function() {
    gBrowser.selectedTab = gBrowser.addTab(url);
  }
  setTimeout(open_tab_callback, 10);
};

let firstRun = function() {
  openTab(adban.FIRST_RUN_URL);

  const nav_bar = $('nav-bar');
  if (!nav_bar) {
    logging.warning('there is no navigation bar in the current window');
    return;
  }
  if ($('adban-button')) {
    logging.warning('the adban-button is already installed (though it is unclear how it is possble)');
    return;
  }

  logging.info('adding adban-button to navigation bar');
  nav_bar.insertItem('adban-button', null, null, false);

  // this 'magic' is necessary for stupid FF, which can't properly handle
  // toolbar.insertItem().
  // See http://forums.mozillazine.org/viewtopic.php?t=189667 .
  nav_bar.setAttribute('currentset', nav_bar.currentSet);
  document.persist('nav-bar', 'currentset');
  logging.info('adban-button must be added to navigation bar');
};

let verifyFirstRun = function(verification_complete_callback) {
  const extensions_getter_callback = function(extensions) {
    const extension = extensions.get(adban.EXTENSION_ID);
    if (extension.firstRun) {
      logging.info('the AdBan first run');
      firstRun();
    }
    verification_complete_callback();
  };
  if (Application.extensions) {
    // Firefox 3.6
    extensions_getter_callback(Application.extensions);
  }
  else {
    // Firefox 4+
    Application.getExtensions(extensions_getter_callback);
  }
};

let stateToggle = function(from, to) {
  to.setAttribute('disabled', 'true');
  from.removeAttribute('disabled');
};

let onStateChange = function(is_active) {
  const cmd_adban_stop = $('cmd-adban-stop');
  const cmd_adban_start = $('cmd-adban-start');
  const adban_button = $('adban-button');
  if (!adban_button) {
    logging.warning('it looks like the adban button has been removed from visible toolbars');
    return;
  }
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
  conditionalAlert('adban-started', _('adban-started'));
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
  logging.info('initializing browser-overlay');
  const first_run_verification_complete = function() {
    // Subscribe to adban state change only after firstRun verification
    // is complete. Otherwise FF4+ won't find adban-button on first run.
    state_listener_id = adban.subscribeToStateChange(onStateChange);
  };
  // defer first run verification due to stupid FF bug, which prevents from
  // toolbar updating immediately in the window.onload event handler.
  // Read more at http://blog.pearlcrescent.com/archives/24 .
  const first_run_callback = function() {
    verifyFirstRun(first_run_verification_complete);
  };
  window.setTimeout(first_run_callback, 10);

  $('cmd-adban-stop').addEventListener('command', cmdStop, false);
  $('cmd-adban-start').addEventListener('command', cmdStart, false);
  $('cmd-adban-complaint').addEventListener('command', cmdComplaint, false);
  $('cmd-adban-help').addEventListener('command', cmdHelp, false);

  // DOMFrameContentLoaded doesn't work as expected,
  // while DOMContentLoaded catches iframes and frames.
  // see https://developer.mozilla.org/en/Gecko-Specific_DOM_Events .
  gBrowser.addEventListener('DOMContentLoaded', adban, true);

  window.addEventListener('unload', shutdown, false);
  logging.info('browser-overlay has been initialized');
};

let shutdown = function() {
  logging.info('shutting down browser-overlay');
  adban.unsubscribeFromStateChange(state_listener_id);
  gBrowser.removeEventListener('DOMContentLoaded', adban, true);

  $('cmd-adban-stop').removeEventListener('command', cmdStop, false);
  $('cmd-adban-start').removeEventListener('command', cmdStart, false);
  $('cmd-adban-complaint').removeEventListener('command', cmdComplaint, false);
  $('cmd-adban-help').removeEventListener('command', cmdHelp, false);

  window.removeEventListener('load', init, false);
  window.removeEventListener('unload', shutdown, false);
  logging.info('browser-overlay has been shut down');
};

window.addEventListener('load', init, false);

