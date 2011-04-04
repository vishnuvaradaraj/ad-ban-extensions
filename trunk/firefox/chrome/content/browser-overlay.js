// use this scoping hack in order to hide objects defined inside the branch
// with the 'let' statement from the global scope.
(function() {
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

  let processDocumentEventHandler = function(e) {
    if (e.type == 'DOMContentLoaded') {
      adban.processDocument(e.originalTarget);
    }
  };

  let enableDocumentsProcessing = function() {
    logging.info('subscribing to DOMContentLoaded event on gBrowser');
    gBrowser.addEventListener('DOMContentLoaded', processDocumentEventHandler, true);
  };

  let disableDocumentsProcessing = function() {
    logging.info('unsubscribing from DOMContentLoaded event on gBrowser');
    gBrowser.removeEventListener('DOMContentLoaded', processDocumentEventHandler, true);
  };

  let onStateChange = function() {
    const cmd_stop = $('adban-cmd-stop');
    const cmd_start = $('adban-cmd-start');
    const toggle_button = $('adban-toggle-button');
    if (adban.isActive()) {
      cmd_start.setAttribute('disabled', 'true');
      cmd_stop.removeAttribute('disabled');
      if (toggle_button) {
        toggle_button.setAttribute('label', _('toggle-button-label-enabled'));
        toggle_button.setAttribute('tooltiptext', _('toggle-button-tooltiptext-enabled'));
      }
      enableDocumentsProcessing();
    }
    else {
      cmd_stop.setAttribute('disabled', 'true');
      cmd_start.removeAttribute('disabled');
      if (toggle_button) {
        toggle_button.setAttribute('label', _('toggle-button-label-disabled'));
        toggle_button.setAttribute('tooltiptext', _('toggle-button-tooltiptext-disabled'));
      }
      disableDocumentsProcessing();
    }
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

  let cmdStop = function() {
    adban.stop();
    conditionalAlert('adban-stopped', _('adban-stopped'));
  };

  let cmdStart = function() {
    adban.start();
    conditionalAlert('adban-started', _('adban-started'));
  };

  let cmdToggle = function() {
    logging.info('toggling AdBan\'s state');
    if (adban.isActive()) {
      cmdStop();
    } else {
      cmdStart();
    }
  };

  let cmdHelp = function() {
    adban.openTab('help', adban.HELP_URL);
  };

  let state_listener_id;
  let is_initially_active;

  let init = function() {
    logging.info('initializing browser-overlay');
    window.removeEventListener('load', init, false);

    $('adban-cmd-complaint').addEventListener('command', cmdComplaint, false);
    $('adban-cmd-stop').addEventListener('command', cmdStop, false);
    $('adban-cmd-start').addEventListener('command', cmdStart, false);
    $('adban-cmd-toggle').addEventListener('command', cmdToggle, false);
    $('adban-cmd-help').addEventListener('command', cmdHelp, false);

    const state_change_results = adban.subscribeToStateChange(onStateChange);
    state_listener_id = state_change_results[0];
    is_initially_active = state_change_results[1];

    // defer first run verification due to FF bug, which prevents from
    // toolbar updating immediately in the window.onload event handler.
    // Read more at http://blog.pearlcrescent.com/archives/24 .
    const first_run_callback = function() {
      if (!pref_branch.prefHasUserValue('first-run')) {
        logging.info('first run of AdBan');
        adban.firstRun();
        setupToolbarButtons();
        showNotification(_('report-ads-notification'), 'report-ads-notification');
        pref_branch.setBoolPref('first-run', true);

        // open help page only after a delay, otherwise it won't
        // be opened under FF3.6 due to unknown reason.
        setTimeout(cmdHelp, 2000);
      }
      onStateChange(is_initially_active);
    };
    adban.executeDeferred(first_run_callback);

    window.addEventListener('unload', shutdown, false);
    logging.info('browser-overlay has been initialized');
  };

  let shutdown = function() {
    logging.info('shutting down browser-overlay');
    window.removeEventListener('unload', shutdown, false);

    if (adban.isActive()) {
      disableDocumentsProcessing();
    }

    adban.unsubscribeFromStateChange(state_listener_id);

    $('adban-cmd-complaint').removeEventListener('command', cmdComplaint, false);
    $('adban-cmd-stop').removeEventListener('command', cmdStop, false);
    $('adban-cmd-start').removeEventListener('command', cmdStart, false);
    $('adban-cmd-toggle').removeEventListener('command', cmdToggle, false);
    $('adban-cmd-help').removeEventListener('command', cmdHelp, false);

    logging.info('browser-overlay has been shut down');
  };

  window.addEventListener('load', init, false);
})();

