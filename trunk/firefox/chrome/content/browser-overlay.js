// use this scoping hack in order to hide objects defined inside the branch
// with the 'let' statement from the global scope.
if (true) {
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

  let setupToolbarButtons = function() {
    const nav_bar = $('nav-bar');
    if (!nav_bar) {
      logging.warning('there is no navigation bar in the current window');
      return;
    }
    if ($('adban-complaint-button')) {
      logging.warning('the adban-complaint-button is already installed (though it is unclear how it is possible)');
      return;
    }

    logging.info('adding adban buttons to navigation bar');
    nav_bar.insertItem('adban-complaint-button', null, null, false);

    // this 'magic' is necessary for FF, which can't properly handle
    // toolbar.insertItem().
    // See http://forums.mozillazine.org/viewtopic.php?t=189667 .
    nav_bar.setAttribute('currentset', nav_bar.currentSet);
    document.persist('nav-bar', 'currentset');
    logging.info('adban buttons must be added to navigation bar');
  };

  let showNotification = function(message, id) {
    const notification_box = gBrowser.getNotificationBox();
    notification_box.appendNotification(message, 'adban-' + id, '', notification_box.PRIORITY_INFO_MEDIUM, null);
  };

  let stateToggle = function(from, to) {
    to.setAttribute('disabled', 'true');
    from.removeAttribute('disabled');
  };

  let onStateChange = function(is_active) {
    const cmd_stop = $('adban-cmd-stop');
    const cmd_start = $('adban-cmd-start');
    if (is_active) {
      stateToggle(cmd_stop, cmd_start);
    }
    else {
      stateToggle(cmd_start, cmd_stop);
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
      const failure_callback = function(error) {
        conditionalAlert('complaint-send-error', _('complaint-send-error', [site_url, error]));
      };
      adban.sendUrlComplaint(site_url, comment, success_callback, failure_callback);
    };

    // Don't use $('urlbar').value as initial_site_url, since this value can be broken.
    // For example, Chrome likes cutting url scheme, while Opera 11 cuts query parameters
    // from the urlbar.
    const initial_site_url = gBrowser.currentURI.spec;
    const complaint_window = openDialog('chrome://adban/content/report-ads-dialog.xul',
        'adban-complaint-window', '', complaint_callback, initial_site_url);
    complaint_window.focus();
  };

  let cmdHelp = function() {
    adban.openTab('help', adban.HELP_URL);
  };

  let state_listener_id;

  let init = function() {
    logging.info('initializing browser-overlay');
    // defer first run verification due to FF bug, which prevents from
    // toolbar updating immediately in the window.onload event handler.
    // Read more at http://blog.pearlcrescent.com/archives/24 .
    const first_run_callback = function() {
      if (!pref_branch.prefHasUserValue('first-run')) {
        logging.info('first run of AdBan');
        setupToolbarButtons();
        showNotification(_('report-ads-notification'), 'report-ads-notification');
        pref_branch.setBoolPref('first-run', true);
      }
      state_listener_id = adban.subscribeToStateChange(onStateChange);
    };
    adban.executeDeferred(first_run_callback);

    $('adban-cmd-stop').addEventListener('command', cmdStop, false);
    $('adban-cmd-start').addEventListener('command', cmdStart, false);
    $('adban-cmd-complaint').addEventListener('command', cmdComplaint, false);
    $('adban-cmd-help').addEventListener('command', cmdHelp, false);

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

    $('adban-cmd-stop').removeEventListener('command', cmdStop, false);
    $('adban-cmd-start').removeEventListener('command', cmdStart, false);
    $('adban-cmd-complaint').removeEventListener('command', cmdComplaint, false);
    $('adban-cmd-help').removeEventListener('command', cmdHelp, false);

    window.removeEventListener('load', init, false);
    window.removeEventListener('unload', shutdown, false);
    logging.info('browser-overlay has been shut down');
  };

  window.addEventListener('load', init, false);
}

