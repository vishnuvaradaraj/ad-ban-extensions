// it is safe defining objects in the global scope of the XPCOM component,
// since they aren't visible outside the component.

const Cu = Components.utils;
const Ci = Components.interfaces;
const Cc = Components.classes;
const Cr = Components.results;

Cu.import('resource://gre/modules/XPCOMUtils.jsm');

const app_info = Cc['@mozilla.org/xre/app-info;1'].getService(Ci.nsIXULAppInfo);

const getCurrentDate = function() {
  return (new Date()).getTime();
};

const logging = {
  levels: {
      INFO: ['INFO', 10],
      WARNING: ['WARNING', 20],
      ERROR: ['ERROR', 30],
      NONE: ['NONE', 40],
  },

  _log_stream: null,
  _level_id: 20,
  _is_active: true,
  _pending_messages: [],

  init: function() {
    this.log(this.levels.NONE, 'name=[%s], version=[%s], appBuildId=[%s], ID=[%s], vendor=[%s], platformBuildID=[%s], platformVersion=[%s]',
        [null, app_info.name, app_info.version, app_info.appBuildID, app_info.ID, app_info.vendor, app_info.platformBuildID, app_info.platformVersion]);
  },

  start: function() {
    this._is_active = true;
    logging.info('logger has been started');
  },

  stop: function() {
    logging.info('logger has been stopped');
    this._is_active = false;
  },

  setLogLevel: function(level) {
    this._level_id = level[1];
  },

  setLogStream: function(log_stream) {
    this._log_stream = log_stream;
    if (log_stream) {
      const pending_messages = this._pending_messages;
      const pending_messages_length = pending_messages.length;
      for (let i = 0; i < pending_messages_length; i++) {
        log_stream.writeString(pending_messages[i]);
      }
      log_stream.flush();
      this._pending_messages = [];
    }
  },

  _log: function(log_string) {
    const log_stream = this._log_stream;
    if (log_stream) {
      log_stream.writeString(log_string);
      log_stream.flush();
    }
    else {
      dump(log_string);
      this._pending_messages.push(log_string);
    }
  },

  log: function(level, msg, args) {
    if (!this._is_active || level[1] < this._level_id) {
      return;
    }
    const msg_parts = msg.split('%s');
    const msg_parts_length = msg_parts.length;
    const formatted_msg_parts = [
      msg_parts[0],
    ];
    for (let i = 1; i < msg_parts_length; i++) {
      formatted_msg_parts.push(args[i], msg_parts[i]);
    };
    const formatted_msg = formatted_msg_parts.join('');
    const date_string = (new Date()).toString();
    const log_string = '['+date_string+'] ['+level[0]+']: '+formatted_msg+'\n';
    this._log(log_string);
  },

  info: function(msg) {
    this.log(this.levels.INFO, msg, arguments);
  },

  warning: function(msg) {
    this.log(this.levels.WARNING, msg, arguments);
  },

  error: function(msg) {
    this.log(this.levels.ERROR, msg, arguments);
  },
};

logging.init();

const getCommonPrefixLength = function(s1, s2) {
  const s1_length = s1.length;
  for (let i = 0; i < s1_length; i++) {
    if (s1[i] != s2[i]) {
      return i;
    }
  }
  return s1_length;
};

const compressStrings = function(s_list) {
  // s_list must be sorted in order to achieve better differential compression.
  const result = [];
  let prev_s = '';
  let common_prefix_length, s;
  const s_list_length = s_list.length;
  for (let i = 0; i < s_list_length; i++) {
    s = s_list[i];
    common_prefix_length = getCommonPrefixLength(prev_s, s);
    result.push(
        common_prefix_length,
        s.substring(common_prefix_length));
    prev_s = s;
  }
  return result;
};

const Trie = function(root_value, node_delete_timeout) {
  const root = this._createNode();
  root.value = root_value;
  root.last_check_date = 0;
  this._root = root;
  this._node_delete_timeout = node_delete_timeout;
};

Trie.importFromNodes = function(root_value, node_delete_timeout, nodes, value_constructor) {
  const trie = new Trie(root_value, node_delete_timeout);
  const nodes_length = nodes.length;
  let key = '';
  let node, common_prefix_length, value, last_check_date;
  for (let i = 0; i < nodes_length; i++) {
    node = nodes[i];
    common_prefix_length = node[0];
    key = key.substring(0, common_prefix_length) + node[1];
    value = value_constructor(node[2]);
    last_check_date = node[3];
    trie.add(key, value, last_check_date);
  }
  return trie;
};

Trie.prototype = {
  _createNode: function() {
    return {
        children: {},
    };
  },

  _mustDeleteNode: function(node, current_date) {
    const last_check_date = node.last_check_date;
    return (last_check_date != 0 && current_date - last_check_date > this._node_delete_timeout);
  },

  _deleteNode: function(node) {
    if (node == this._root) {
      // don't delete root node.
      node.last_check_date = 0;
    }
    else {
      delete node.value;
      delete node.last_check_date;
    }

    const children = node.children;
    for (let c in children) {
      node = children[c];
      if ('value' in node && node.last_check_date == 0) {
        delete node.value;
        delete node.last_check_date;
      }
    }
  },

  _get: function(key, current_date) {
    const key_length = key.length;
    let node = this._root;
    let node_with_value = node;
    let node_depth = 0;
    let tmp_node, c;
    while (node_depth < key_length) {
      c = key[node_depth];
      tmp_node = node.children[c];
      if (!tmp_node) {
        break;
      }
      if ('value' in tmp_node) {
        if (this._mustDeleteNode(tmp_node, current_date)) {
          this._deleteNode(tmp_node);
        }
        else {
          node_with_value = tmp_node;
        }
      }
      node_depth++;
      node = tmp_node;
    }
    return [node, node_with_value, node_depth];
  },

  _clearNodesWithValue: function(node, node_depth, end_key) {
    const end_key_length = end_key.length;
    let tmp_node, c;
    while (node_depth < end_key_length) {
      c = end_key[node_depth];
      tmp_node = node.children[c];
      if (!tmp_node) {
        break;
      }
      node = tmp_node;
      if ('value' in node) {
        delete node.value;
        delete node.last_check_date;
      }
      node_depth++;
    }
  },

  _getNodes: function(key, node) {
    if ('value' in node) {
      if (this._mustDeleteNode(node, this._current_date)) {
        this._deleteNode(node);
      }
      else {
        const common_prefix_length = getCommonPrefixLength(this._prev_key, key);
        this._nodes.push([
            common_prefix_length,
            key.substring(common_prefix_length),
            this._node_constructor(node.value),
            node.last_check_date,
        ]);
        this._prev_key = key;
      }
    }
    const children = node.children;
    for (let c in children) {
      this._getNodes(key + c, children[c]);
    }
  },

  get: function(key, current_date) {
    return this._get(key, current_date)[1];
  },

  add: function(key, value, current_date) {
    const key_length = key.length;
    const tmp = this._get(key, current_date);
    let node = tmp[0];
    let node_depth = tmp[2];
    let new_node, c;
    while (node_depth < key_length) {
      c = key[node_depth];
      new_node = this._createNode();
      node.children[c] = new_node;
      node = new_node;
      node_depth++;
    }
    node.value = value;
    node.last_check_date = current_date;
    return node;
  },

  update: function(start_key, end_keys, value, current_date, todo, todo_value) {
    const tmp = this._get(start_key, current_date);
    const node = tmp[0];
    const node_depth = tmp[2];
    if (node_depth == start_key.length) {
      const end_keys_length = end_keys.length;
      for (let i = 0; i < end_keys_length; i++) {
        this._clearNodesWithValue(node, node_depth, end_keys[i]);
      }
    }

    const added_node = this.add(start_key, value, current_date);
    const children = added_node.children;
    const todo_length = todo.length;
    for (let i = 0; i < todo_length; i++) {
      let c = todo[i];
      let child_node = children[c];
      if (!child_node) {
        child_node = this._createNode();
        children[c] = child_node;
      }
      else if (child_node.last_check_date) {
        // do not modify already existing node.
        continue;
      }
      // it is OK that multiple nodes share the same reference
      // to the todo_value if the value contents is immutable.
      // Otherwise modification of a node's value could break other node's
      // value.
      child_node.value = todo_value;
      child_node.last_check_date = 0;
    }
  },

  exportToNodes: function(node_constructor, current_date) {
    const nodes = [];
    this._prev_key = '';
    this._nodes = nodes;
    this._node_constructor = node_constructor;
    this._current_date = current_date;
    this._getNodes('', this._root);
    return nodes;
  },

  setNodeDeleteTimeout: function(node_delete_timeout) {
    this._node_delete_timeout = node_delete_timeout;
  },
};

// It is OK to share default values by reference among multiple Trie nodes,
// because node values are considered immutable.
// WARNING: if sometimes node values will become mutable, then these default values
// must be distinctly cloned for each Trie node.
const defaultUrlValue = {
    is_whitelist: true,
};

const defaultUrlExceptionValue = {
};

const createEmptyUrlCache = function(node_delete_timeout) {
  return new Trie(defaultUrlValue, node_delete_timeout);
};

const createEmptyUrlExceptionCache = function(node_delete_timeout) {
  return new Trie(defaultUrlExceptionValue, node_delete_timeout);
};

const BLACKLISTED_CANONICAL_URLS_BIT_MASK = (1 << 0);
const WHITELISTED_CANONICAL_URLS_BIT_MASK = (1 << 1);
const CSS_SELECTORS_BIT_MASK = (1 << 2);

const urlNodeConstructor = function(v) {
  return (v.is_whitelist + 0);
};

const urlExceptionNodeConstructor = function(v) {
  const blacklisted_canonical_urls = v.blacklisted_canonical_urls;
  const whitelisted_canonical_urls = v.whitelisted_canonical_urls;
  const css_selectors = v.css_selectors;

  let d_bitmap = 0;
  const d = [];
  if (blacklisted_canonical_urls) {
    d_bitmap |= BLACKLISTED_CANONICAL_URLS_BIT_MASK;
    d.push(blacklisted_canonical_urls.source);
  }
  if (whitelisted_canonical_urls) {
    d_bitmap |= WHITELISTED_CANONICAL_URLS_BIT_MASK;
    d.push(whitelisted_canonical_urls.source);
  }
  if (css_selectors) {
    d_bitmap |= CSS_SELECTORS_BIT_MASK;
    d.push(css_selectors);
  }
  d.push(d_bitmap);
  return d;
};

const urlValueConstructor = function(d) {
  return {
      is_whitelist: !!(d & 1),
  };
};

const urlExceptionValueConstructor = function(d) {
  const v = {};
  const d_bitmap = d.pop();
  let i = 0;
  if (d_bitmap & BLACKLISTED_CANONICAL_URLS_BIT_MASK) {
    v.blacklisted_canonical_urls = new RegExp(d[i]);
    i++;
  }
  if (d_bitmap & WHITELISTED_CANONICAL_URLS_BIT_MASK) {
    v.whitelisted_canonical_urls = new RegExp(d[i]);
    i++;
  }
  if (d_bitmap & CSS_SELECTORS_BIT_MASK) {
    v.css_selectors = d[i];
    i++;
  }
  return v;
};

const AdBan = function() {
  logging.info('entering AdBan constructor');
  this.pref_branch = this._pref_service.getBranch('extensions.' + this.EXTENSION_ID + '.');
  this.HELP_URL = this._SERVER_HOST + '/ff/help';
  this.USER_STATUS_URL = this._SERVER_HOST + '/ff/user_status';

  // allow direct access to the XPCOM object from javascript.
  // see https://developer.mozilla.org/en/wrappedJSObject .
  this.wrappedJSObject = this;
  logging.info('exiting AdBan constructor');
};

AdBan.prototype = {
  // XPCOM stuff.
  classDescription: 'AdBan XPCOM component',
  classID:          Components.ID('{02f31d71-1c0b-48f3-a3b5-100c18dc771e}'),
  contractID:       '@ad-ban.appspot.com/adban;1',
  _xpcom_categories: [
      {category: 'app-startup', service: true},
  ],
  QueryInterface: XPCOMUtils.generateQI([
      Ci.nsIChannelEventSink,
      Ci.nsIContentPolicy,
      Ci.nsIDOMEventListener,
      Ci.nsIObserver,
  ]),

  // constants
  _ACCEPT: Ci.nsIContentPolicy.ACCEPT,
  _REJECT: Ci.nsIContentPolicy.REJECT_REQUEST,
  _REJECT_EXCEPTION: Cr.NS_BASE_STREAM_WOULD_BLOCK,
  _DATA_DIRECTORY_NAME: 'adban',
  _SETTINGS_FILENAME: 'settings.json',
  _CACHE_FILENAME: 'cache.json',
  _LOGS_FILENAME: 'log.txt',
  _FILTERED_SCHEMES: {
      http: true,
      https: true,
      ftp: true,
  },
  _SERVER_HOST: 'https://ad-ban.appspot.com',
  _AUTH_COOKIE_HOST: 'ad-ban.appspot.com',
  _ERROR_CODES: {
      NO_ERRORS: 0,
      REQUEST_PARSING_ERROR: 1,
      AUTHENTICATION_ERROR: 3,
      AUTHORIZATION_ERROR: 4,
      OTHER_ERROR: -1,
  },

  // helper XPCOM objects
  _verify_urls_xhr: Cc['@mozilla.org/xmlextras/xmlhttprequest;1'].createInstance(Ci.nsIXMLHttpRequest),
  _update_settings_xhr: Cc['@mozilla.org/xmlextras/xmlhttprequest;1'].createInstance(Ci.nsIXMLHttpRequest),
  _url_complaint_xhr: Cc['@mozilla.org/xmlextras/xmlhttprequest;1'].createInstance(Ci.nsIXMLHttpRequest),
  _json_encoder: Cc['@mozilla.org/dom/json;1'].createInstance(Ci.nsIJSON),
  _converter: Cc['@mozilla.org/intl/scriptableunicodeconverter'].createInstance(Ci.nsIScriptableUnicodeConverter),
  _category_manager: Cc['@mozilla.org/categorymanager;1'].getService(Ci.nsICategoryManager),
  _window_mediator: Cc['@mozilla.org/appshell/window-mediator;1'].getService(Ci.nsIWindowMediator),
  _directory_service: Cc['@mozilla.org/file/directory_service;1'].getService(Ci.nsIProperties),
  _io_service: Cc['@mozilla.org/network/io-service;1'].getService(Ci.nsIIOService),
  _observer_service: Cc['@mozilla.org/observer-service;1'].getService(Ci.nsIObserverService),
  _pref_service: Cc['@mozilla.org/preferences-service;1'].getService(Ci.nsIPrefService),
  _cookie_manager: Cc['@mozilla.org/cookiemanager;1'].getService(Ci.nsICookieManager2),
  _main_thread: Cc['@mozilla.org/thread-manager;1'].getService().mainThread,
  _verify_urls_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _read_settings_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _update_current_date_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _update_settings_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _save_cache_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),

  // this logging must be accessible outside the AdBan component.
  logging: logging,

  // id of the AdBan extension (see install.rdf)
  EXTENSION_ID: 'adban@ad-ban.appspot.com',

  // component's settings. New values for these settings are periodically read
  // from the server.
  _settings: {
    url_verifier_delay: 1000 * 2,
    stale_node_timeout: 1000 * 3600 * 24,
    node_delete_timeout: 1000 * 3600 * 24 * 30,
    current_date_granularity: 1000 * 10,
    update_settings_interval: 1000 * 3600 * 24,
    max_url_length: 50,
    max_url_exception_length: 50,
    save_cache_interval: 1000 * 60 * 20,

    read_settings_delay: 1000 * 5,  // this value isn't changed.

    import: function(data) {
      this.url_verifier_delay = data[0];
      this.stale_node_timeout = data[1];
      this.node_delete_timeout = data[2];
      this.current_date_granularity = data[3];
      this.update_settings_interval = data[4];
      this.max_url_length = data[5];
      this.max_url_exception_length = data[6];

      // the following condition is required for backwards compatibility
      // if the save_cache_interval is missing in the file with old settings.
      const save_cache_interval = data[7];
      if (save_cache_interval) {
        this.save_cache_interval = save_cache_interval;
      }
    },

    export: function() {
      return [
          this.url_verifier_delay,
          this.stale_node_timeout,
          this.node_delete_timeout,
          this.current_date_granularity,
          this.update_settings_interval,
          this.max_url_length,
          this.max_url_exception_length,
          this.save_cache_interval,
      ];
    },
  },

  // These properties can be re-assigned by the component.
  // Encapsulate them into the _vars object in the component's prototype,
  // so re-assigning of these properties will occur in the prototype,
  // not the component instance itself. This allows sharing these properties
  // among all instances of the component, which could be created by FireFox
  // via createInstance() call instead of getService() call.
  _vars: {
    current_date: getCurrentDate(),
    auth_token: '',
    url_cache: createEmptyUrlCache(0),
    url_exception_cache: createEmptyUrlExceptionCache(0),
    unverified_urls: {},
    unverified_url_exceptions: {},
    is_url_verifier_active: false,
    is_active: false,
    is_in_private_mode: false,
    is_app_startup_called: false,
  },

  _state_listeners: {},
  _last_state_listener_id: 0,

  // net-channel-event-sinks category event handler
  onChannelRedirect: function(old_channel, new_channel, flags) {
    logging.info('redirect from [%s] to [%s]', old_channel.URI.spec, new_channel.URI.spec);

    // there is no need in verifying the old_channel, because it must be
    // already verified by shouldLoad() content-policy handler.
    // So verify only the new_channel.
    const request_origin = this._getRequestOriginFromChannel(new_channel);
    if (!this._verifyLocation(new_channel.URI, request_origin)) {
      throw this._REJECT_EXCEPTION;
    }
  },

  // net-channel-event-sinks category event handler for Firefox 4+.
  // See https://developer.mozilla.org/en/XPCOM_Interface_Reference/nsIChannelEventSink .
  asyncOnChannelRedirect: function(old_channel, new_channel, flags, callback) {
    this.onChannelRedirect(old_channel, new_channel, flags);
    callback.onRedirectVerifyCallback(Cr.NS_OK);
  },

  // content-policy category event handler
  shouldLoad: function(content_type, content_location, request_origin, node, mime_type, extra) {
    if (this._verifyLocation(content_location, request_origin)) {
      return this._ACCEPT;
    }

    if (content_type == Ci.nsIContentPolicy.TYPE_DOCUMENT) {
      const w = node.contentWindow;
      if (w && w.opener && w.top != w.opener.top) {
        try {
          logging.info('closing the popup [%s] opened by the [%s]', content_location.spec, w.opener.location.href);
          w.close();
        }
        catch(e) {
          logging.error('cannot close the popup [%s]: [%s]', content_location.spec, e);
        }
      }
    }

    return this._REJECT;
  },
  shouldProcess: function(content_type, content_location, request_origin, node, mime_type, extra) {
    return this._ACCEPT;
  },

  // nsIDOMEventListener implementation
  handleEvent: function(e) {
    if (!this._vars.is_active) {
      return;
    }

    if (e.type == 'DOMContentLoaded') {
      const doc = e.originalTarget;
      const node_name = doc.nodeName;
      if (node_name != '#document') {
        logging.info('the current DOMContentLoaded target=[%s] isn\'t html document', node_name);
        return;
      }
      const site_url = doc.location.href;
      logging.info('DOMContentLoaded event on url=[%s]', site_url);
      const site_uri = this._createUri(site_url);
      if (!this._shouldProcessUri(site_uri)) {
        logging.info('there is no need in processing the url=[%s]', site_url);
        return;
      }
      this._injectCssToDocument(doc, site_uri);
      this._prefetchAdFiltersForDocumentLinks(doc);
    }
  },

  // nsIObserver implementation
  observe: function(subject, topic, data) {
    const observer_service = this._observer_service;
    const vars = this._vars;
    if (topic == 'app-startup') {
      logging.info('app-startup');
      // The 'app-startup' event isn't fired in FF4, so perform
      // all initialization at 'profile-after-change' step,
      // which is the only available in FF4.
      // See https://developer.mozilla.org/en/XPCOM/XPCOM_changes_in_Gecko_2.0 .
      vars.is_app_startup_called = true;
      observer_service.addObserver(this, 'profile-after-change', false);
    }
    else if (topic == 'profile-after-change') {
      logging.info('profile-after-change');
      this._setupLogging();
      observer_service.addObserver(this, 'quit-application', false);
      observer_service.addObserver(this, 'private-browsing', false);
      try {
        const private_browsing_service = Cc['@mozilla.org/privatebrowsing;1'].getService(Ci.nsIPrivateBrowsingService);
        if (private_browsing_service.privateBrowsingEnabled) {
          logging.info('private mode is on at browser start');
          logging.stop();
          vars.is_in_private_mode = true;
        }
      }
      catch(e) {
        logging.warning('it seems the browser doesn\'t support private browsing');
      }
      this._converter.charset = 'UTF-8';
      this._loadSettingsAsync();
      this._loadCacheAsync();
      this.start();
    }
    else if (topic == 'private-browsing') {
      if (data == 'enter') {
        // save the current cache to local storage, so it can be loaded later
        // after exiting the private mode. The cache created during private mode
        // won't be saved to local storage.

        // The cache cannot be stored asynchronously here, since this can lead
        // to the following race conditions:
        // - saveCache operation has been started, browser enters private
        //   mode and adds new entries to cache, so they eventually are saved
        //   to local storage after saveCache is complete.
        // - saveCache operation has been started, browser exits private mode
        //   and starts loading cache back from the local storage, which can
        //   be in inconsistent state because of saveCache operation isn't
        //   complete yet.
        this._saveCacheSync();
        logging.info('entering private browsing mode');
        logging.stop();
        vars.is_in_private_mode = true;
      }
      else if (data == 'exit') {
        logging.start();
        logging.info('exiting private browsing mode');
        // load cache from local storage, which were saved before entering
        // the private mode. The loaded cache will overwrite the current cache,
        // wich can contain private data.
        this._loadCacheAsync();
        vars.is_in_private_mode = false;
      }
    }
    else if (topic == 'quit-application') {
      logging.info('quit-application');
      this.stop();

      // The cache cannot be stored asynchronously here, since the browser
      // process can exit before the saveCache operation is complete.
      // This can leave locally stored cache in inconsistent state.
      this._saveCacheSync();

      observer_service.removeObserver(this, 'private-browsing');
      observer_service.removeObserver(this, 'quit-application');
      if (vars.is_app_startup_called) {
        observer_service.removeObserver(this, 'profile-after-change');
      }
    }
  },

  // publicly accessed methods.
  start: function() {
    const vars = this._vars;
    if (vars.is_active) {
      logging.warning('AdBan component already started');
      return;
    }
    const category_manager = this._category_manager;
    category_manager.addCategoryEntry('content-policy', this.classDescription, this.contractID, false, false);
    category_manager.addCategoryEntry('net-channel-event-sinks', this.classDescription, this.contractID, false, false);
    this._startTimers();
    vars.is_active = true;
    this._notifyStateListeners(true);
    logging.info('AdBan component has been started');
  },

  stop: function() {
    const vars = this._vars;
    if (!vars.is_active) {
      logging.warning('AdBan component already stopped');
      return;
    }
    this._stopTimers();
    const category_manager = this._category_manager;
    category_manager.deleteCategoryEntry('net-channel-event-sinks', this.classDescription, false);
    category_manager.deleteCategoryEntry('content-policy', this.classDescription, false);
    vars.is_active = false;
    this._notifyStateListeners(false);
    logging.info('AdBan component has been stopped');
  },

  sendUrlComplaint: function(site_url, comment, success_callback, failure_callback) {
    logging.info('sending url complaint for site_url=[%s], comment=[%s]', site_url, comment);
    const request_data = [site_url, comment];
    const request_url = this._SERVER_HOST + '/c';

    const response_callback = function() {
      success_callback();
    };
    const finish_callback = function(message) {
      if (message) {
        failure_callback(message);
      }
    };
    this._startJsonRequest(this._url_complaint_xhr, request_url, request_data, response_callback, finish_callback);
  },

  subscribeToStateChange: function(state_change_callback) {
    logging.info('subscribing to AdBan component state change');
    const listener_id = this._last_state_listener_id++;
    this._state_listeners[listener_id] = state_change_callback;
    return [listener_id, this._vars.is_active];
  },

  unsubscribeFromStateChange: function(listener_id) {
    logging.info('unsubscribing from AdBan component state change. listener_id=[%s]', listener_id);
    delete this._state_listeners[listener_id];
  },

  executeDeferred: function(callback) {
    const main_thread = this._main_thread;
    const thread_event = {
        run: callback,
    };
    main_thread.dispatch(thread_event, main_thread.DISPATCH_NORMAL);
  },

  openTab: function(tab_name, url) {
    // open a tab asynchronously, since this operation can block in contexts,
    // where blocking is prohibited.
    const that = this;
    const open_tab_callback = function() {
      that._openTabInternal(tab_name, url);
    };
    this.executeDeferred(open_tab_callback);
  },

  // private methods
  _openTabInternal: function(tab_name, url) {
    logging.info('opening a tab [%s], url=[%s]', tab_name, url);

    // this code has been stolen from https://developer.mozilla.org/en/Code_snippets/Tabbed_browser#Reusing_tabs .
    const browser_window = this._window_mediator.getMostRecentWindow('navigator:browser');
    if (!browser_window) {
      logging.error('there are no open browser windows');
      return;
    }

    const tab_browser = browser_window.gBrowser;
    const tabs = tab_browser.tabContainer.childNodes;
    const tabs_count = tabs.length;
    const attribute_name = 'adban-tab-' + tab_name;
    let tab;
    for (let i = 0; i < tabs_count; i++) {
      tab = tabs[i];
      if (tab.hasAttribute(attribute_name)) {
        logging.info('the tab [%s] is already opened', tab_name);
        tab_browser.selectedTab = tab;
        return;
      }
    }

    logging.info('openining new tab [%s]', tab_name);
    tab = tab_browser.addTab(url);
    tab.setAttribute(attribute_name, 'true');
    tab_browser.selectedTab = tab;
    logging.info('the tab [%s], url=[%s] has been opened', tab_name, url);
  },

  _notifyStateListeners: function(is_active) {
    const state_listeners = this._state_listeners;
    for (let listener_id in state_listeners) {
      logging.info('notifying AdBan component state listener [%s]', listener_id);
      state_listeners[listener_id](is_active);
    }
  },

  _setupLogging: function() {
    logging.info('initializing global log stream');
    const log_file = this._getFileForLogs();
    const log_file_stream = Cc['@mozilla.org/network/file-output-stream;1'].createInstance(Ci.nsIFileOutputStream);
    const io_flags = 0x02 | 0x08 | 0x10;  // open for writing (0x02), create if doesn't exist (0x08) and appending (0x10).
    log_file_stream.init(log_file, io_flags, -1, 0);
    const log_stream = Cc['@mozilla.org/intl/converter-output-stream;1'].createInstance(Ci.nsIConverterOutputStream);
    log_stream.init(log_file_stream, 'UTF-8', 0, 0);
    logging.setLogStream(log_stream);
    logging.info('global log stream has been initialized');

    const pref_branch = this.pref_branch;
    if (pref_branch.prefHasUserValue('log-level')) {
      const log_level_name = pref_branch.getCharPref('log-level');
      const log_level = logging.levels[log_level_name];
      if (log_level) {
        logging.info('setting log_level to [%s]', log_level_name);
        logging.setLogLevel(log_level);
      }
    }
  },

  _startRepeatingTimer: function(timer, callback, interval) {
    const timer_callback = {
        notify: callback,
    };
    timer.initWithCallback(timer_callback, interval, timer.TYPE_REPEATING_SLACK);
  },

  _executeDelayed: function(timer, callback, delay) {
    const timer_callback = {
        notify: callback,
    };
    timer.initWithCallback(timer_callback, delay, timer.TYPE_ONE_SHOT);
  },

  _startTimers: function() {
    logging.info('starting AdBan component timers');
    const that = this;
    const settings = this._settings;

    // it is safe re-initializing timers in-place -
    // in this case the first callback will be automatically canceled.
    // See https://developer.mozilla.org/En/nsITimer .
    const update_current_date_callback = function() {
      that._vars.current_date = getCurrentDate();
    };
    update_current_date_callback();
    this._startRepeatingTimer(
        this._update_current_date_timer,
        update_current_date_callback,
        settings.current_date_granularity);

    const update_settings_callback = function() {
      that._readSettingsFromServer();
    };
    this._startRepeatingTimer(
        this._update_settings_timer,
        update_settings_callback,
        settings.update_settings_interval);

    const save_cache_callback = function() {
      that._saveCacheSync();
    };
    this._startRepeatingTimer(
        this._save_cache_timer,
        save_cache_callback,
        settings.save_cache_interval);
    logging.info('AdBan component timers have been started');
  },

  _stopTimers: function() {
    logging.info('stopping AdBan component timers');
    // canceled timers can be re-used later.
    // See https://developer.mozilla.org/En/nsITimer#cancel() .
    this._update_current_date_timer.cancel();
    this._update_settings_timer.cancel();
    this._save_cache_timer.cancel();
    logging.info('AdBan component timers have been stopped');
  },

  _createUri: function(url) {
    // TODO: verify if url contains non-ascii chars.
    return this._io_service.newURI(url, null, null);
  },

  _getRequestOriginFromChannel: function(channel) {
    // I don't know how does this code work. It has been copy-pasted from
    // https://developer.mozilla.org/en/Code_snippets/Tabbed_browser#Getting_the_browser_that_fires_the_http-on-modify-request_notification .
    let request_origin = null;
    const cb = channel.notificationCallbacks ? channel.notificationCallbacks : channel.loadGroup.notificationCallbacks;
    if (cb) {
      try {
        const w = cb.getInterface(Ci.nsIDOMWindow);
        let origin_url = w.document.location.href;
        if (origin_url == 'about:blank') {
          // Iframe's window is 'about:blank'. Use url for the parent
          // window instead.
          origin_url = w.parent.document.location.href;
        }
        request_origin = this._createUri(origin_url);
      }
      catch(e) {
        // It looks like css channels don't provide nsIDOMWindow
        // during redirects. Just silently skip this, because it is unclear
        // how to determine the request_origin in this case.
        logging.warning('error when obtaining request origin from channel: [%s]', e);
      }
    }
    return request_origin;
  },

  _getDataDirectory: function() {
    const data_dir = this._directory_service.get('ProfD', Ci.nsIFile);
    data_dir.append(this._DATA_DIRECTORY_NAME);
    if (!data_dir.exists() || !data_dir.isDirectory()) {
      logging.info('creating data directory for AdBan plugin: [%s]', data_dir.path);
      data_dir.create(data_dir.DIRECTORY_TYPE, 0774);
    }
    return data_dir.clone();
  },

  _getFileForSettings: function() {
    const file = this._getDataDirectory();
    file.append(this._SETTINGS_FILENAME);
    return file;
  },

  _getFileForCaches: function() {
    const file = this._getDataDirectory();
    file.append(this._CACHE_FILENAME);
    return file;
  },

  _getFileForLogs: function() {
    const file = this._getDataDirectory();
    file.append(this._LOGS_FILENAME);
    return file;
  },

  _readJsonFromFileAsync: function(file, read_complete_callback) {
    logging.info('start reading from the file=[%s]', file.path);
    if (!file.exists()) {
      logging.warning('the file [%s] doesn\'t exist, skipping loading from file', file.path);
      return;
    }
    const ios = this._io_service;
    const fileURI = ios.newFileURI(file);
    const channel = ios.newChannelFromURI(fileURI);
    const that = this;
    const observer = {
        onStreamComplete : function(loader, context, status, length, result) {
          if (!Components.isSuccessCode(status)) {
            logging.error('error when reading the file=[%s], status=[%s]', file.path, status);
            return;
          }
          try {
            const json_data = that._converter.convertFromByteArray(result, length);
            const data = that._json_encoder.decode(json_data);
            logging.info('stop reading from the file=[%s]', file.path);
            read_complete_callback(data);
          }
          catch(e) {
            logging.error('error when reading and parsing json from the file=[%s]: [%s]', file.path, e);
          }
        },
    };
    const stream_loader = Cc['@mozilla.org/network/stream-loader;1'].createInstance(Ci.nsIStreamLoader);
    stream_loader.init(observer);
    channel.asyncOpen(stream_loader, null);
  },

  _writeJsonToFileSync: function(file, data) {
    logging.info('start writing to the file=[%s]', file.path);
    const json_data = this._json_encoder.encode(data);
    const data_chunk = this._converter.ConvertFromUnicode(json_data);
    const output_stream = Cc['@mozilla.org/network/file-output-stream;1'].createInstance(Ci.nsIFileOutputStream);
    output_stream.init(file, -1, -1, 0);
    // Note: these blocking functions can lock UI for a short period of time,
    // but this should be OK in most cases :). Non-blocking solutions are much
    // more complex and suffer from race conditions.
    output_stream.write(data_chunk, data_chunk.length);
    output_stream.close();
    logging.info('stop writing to the file=[%s]', file.path);
  },

  _loadSettingsAsync: function() {
    logging.info('loading AdBan settings from file');
    const file = this._getFileForSettings();
    const that = this;
    const read_complete_callback = function(data) {
      that._vars.auth_token = data[0];
      that._settings.import(data[1]);
      logging.info('AdBan settings have been loaded from file');
    };
    this._readJsonFromFileAsync(file, read_complete_callback);

    // read settings from the server with little delay, so the browser will
    // be ready to send XHR requests.
    const read_settings_callback = function() {
      that._readSettingsFromServer();
    };
    that._executeDelayed(this._read_settings_timer, read_settings_callback, this._settings.read_settings_delay);
  },

  _saveSettingsSync: function() {
    logging.info('saving AdBan settings to file');
    const data = [
      this._vars.auth_token,
      this._settings.export(),
    ];
    const file = this._getFileForSettings();
    this._writeJsonToFileSync(file, data);
    logging.info('AdBan settings have been saved to file');
  },

  _loadCacheAsync: function() {
    logging.info('loading AdBan cache from file');
    const that = this;
    const vars = this._vars;
    const node_delete_timeout = this._settings.node_delete_timeout;
    const file = this._getFileForCaches();
    const read_complete_callback = function(data) {
      const url_cache = Trie.importFromNodes(
          defaultUrlValue,
          node_delete_timeout,
          data[0],
          urlValueConstructor);
      const url_exception_cache = Trie.importFromNodes(
          defaultUrlExceptionValue,
          node_delete_timeout,
          data[1],
          urlExceptionValueConstructor);
      vars.url_cache = url_cache;
      vars.url_exception_cache = url_exception_cache;
      logging.info('AdBan cache has been loaded from file');
    };
    this._readJsonFromFileAsync(file, read_complete_callback);
  },

  _saveCacheSync: function() {
    logging.info('saving AdBan cache to file');
    const vars = this._vars;
    if (vars.is_in_private_mode) {
      logging.info('cache shouldn\'t be saved while in private mode');
      return;
    }
    const current_date = vars.current_date;
    const url_cache = vars.url_cache;
    const url_exception_cache = vars.url_exception_cache;
    const data = [
        url_cache.exportToNodes(urlNodeConstructor, current_date),
        url_exception_cache.exportToNodes(urlExceptionNodeConstructor, current_date),
    ]
    const file = this._getFileForCaches();
    this._writeJsonToFileSync(file, data);
    logging.info('AdBan cache has been saved to file');
  },

  _shouldProcessUri: function(url) {
    return (url.scheme in this._FILTERED_SCHEMES);
  },

  _injectCssToDocument: function(doc, site_uri) {
    const canonical_site_url = this._getCanonicalUrl(site_uri);
    const url_exception_value = this._getUrlExceptionValue(canonical_site_url);
    const css_selectors = url_exception_value.css_selectors;

    if (css_selectors) {
      const style = doc.createElement('style');
      style.type = 'text/css';
      const style_text = css_selectors + '{display: none !important;}';
      const style_text_node = doc.createTextNode(style_text);
      style.appendChild(style_text_node);
      logging.info('adding css selector=[%s] to the site_url=[%s]', style_text, site_uri.spec);
      doc.getElementsByTagName('head')[0].appendChild(style);
    }
  },

  _prefetchAdFiltersForDocumentLinks: function(doc) {
    const links = doc.links;
    const links_length = links.length;
    for (let i = 0; i < links_length; i++) {
      let link = links[i];
      let uri = this._createUri(link.href);
      if (!this._shouldProcessUri(uri)) {
        logging.info('there is no need in processing the link=[%s]', uri.spec);
        continue;
      }
      let canonical_url = this._getCanonicalUrl(uri);
      let value = this._getUrlValue(canonical_url);
      let is_whitelist = value.is_whitelist;
      this._getUrlExceptionValue(canonical_url);
      if (!is_whitelist) {
        logging.info('hiding the link=[%s]', canonical_url);
        link.style.display = 'none';
      }
    }
  },

  _updateCache: function(response_data, urls, cache, value_constructor, default_value) {
    const response_data_length = response_data.length;

    for (let i = 0; i < response_data_length; i++) {
      const data = response_data[i];
      const url_length = data[0];
      const todo = data[1];
      const url_idx = data[2];
      const properties = data[3];

      const end_urls = [];
      const url_idx_length = url_idx.length;
      for (let j = 0; j < url_idx_length; j++) {
        end_urls[j] = urls[url_idx[j]];
      }
      const url = urls[url_idx[0]].substring(0, url_length);
      const value = value_constructor(properties);
      cache.update(url, end_urls, value, this._vars.current_date, todo, default_value);
    }
  },

  _getDictionaryKeys: function(dict) {
    const keys = [];
    for (let key in dict) {
      keys.push(key);
    }
    return keys;
  },

  _cleanupUnverifiedUrls: function(unverified_urls, cache) {
    const current_date = this._vars.current_date;
    const urls = this._getDictionaryKeys(unverified_urls);
    const urls_length = urls.length;
    for (let i = 0; i < urls_length; i++) {
      let url = urls[i];
      let cache_node = cache.get(url, current_date);
      if (!this._isStaleCacheNode(cache_node)) {
        logging.info('the url [%s] is already verified', url);
        delete unverified_urls[url];
      }
    }
  },

  _injectAuthTokenToCookie: function(auth_token) {
    const host = this._AUTH_COOKIE_HOST;
    logging.info('injecting auth_token=[%s] into cookie for the host=[%s]', auth_token, host);
    const expiration_time = 0x7fffffff;
    // see https://developer.mozilla.org/en/XPCOM_Interface_Reference/nsICookieManager2#add() .
    this._cookie_manager.add(host, '/', 'a', auth_token, true, false, false, expiration_time);
  },

  _processJsonResponse: function(request_text, response_text, response_callback) {
    const error_codes = this._ERROR_CODES;
    const vars = this._vars;
    let error_message;

    logging.info('response_text=[%s]', response_text);
    const response_data = this._json_encoder.decode(response_text);
    const error_code = response_data[0];
    if (error_code == error_codes.NO_ERRORS) {
      const new_auth_token = response_data[2];
      if (new_auth_token) {
        logging.info('obtained new auth_token=[%s] from the response_text=[%s]. request_text=[%s]', new_auth_token, response_text, request_text);
        vars.auth_token = new_auth_token;
        this._injectAuthTokenToCookie(new_auth_token);
      }
      if (response_callback) {
        response_callback(response_data[1]);
      }
    }
    else if (error_code == error_codes.AUTHENTICATION_ERROR) {
      logging.error('authentication failed for auth_token=[%s]. Resetting the auth_token.', vars.auth_token);
      vars.auth_token = '';
      error_message = 'authentication error';
    }
    else if (error_code == error_codes.AUTHORIZATION_ERROR) {
      logging.warning('authorization failed for auth_token=[%s]', vars.auth_token);
      this.openTab('user-status', this.USER_STATUS_URL);
      error_message = 'authorization error';
    }
    else {
      logging.error('server responded with the error_code=[%s] for the request_text=[%s]. response_text=[%s]', error_code, request_text, response_text);
      error_message = 'unexpected server error';
    }
    return error_message;
  },

  _startJsonRequest: function(xhr, request_url, request_data, response_callback, finish_callback) {
    const auth_token = this._vars.auth_token;
    let finish_callback_message;

    const request_text = this._json_encoder.encode([auth_token, request_data]);
    logging.info('request_url=[%s], request_text=[%s]', request_url, request_text);

    const that = this;
    xhr.open('POST', request_url);
    xhr.onreadystatechange = function() {
      if (xhr.readyState == 4) {
        try {
          const http_status = xhr.status;
          if (http_status == 200) {
            finish_callback_message = that._processJsonResponse(request_text, xhr.responseText, response_callback);
          }
          else {
            logging.error('unexpected HTTP status code for the request_url=[%s], request_text=[%s], http_status=[%s]', request_url, request_text, http_status);
            finish_callback_message = 'server error';
          }
        }
        catch(e) {
          logging.error('error when processing json response=[%s] for the request_url=[%s], request_text=[%s]: [%s]', xhr.responseText, request_url, request_text, e);
          finish_callback_message = 'protocol error';
        }
        finally {
          if (finish_callback) {
            finish_callback(finish_callback_message);
          }
        }
      }
    };
    const encoded_request = encodeURIComponent(request_text);
    xhr.send(encoded_request);
  },

  _readSettingsFromServer: function() {
    const request_data = [];
    const settings = this._settings;
    const vars = this._vars;
    const that = this;
    const response_callback = function(response) {
      settings.import(response);
      // save settings on the local storage syncrhonously to be sure they
      // are stored in a consistent state.
      that._saveSettingsSync();
      that._startTimers();
      vars.url_cache.setNodeDeleteTimeout(settings.node_delete_timeout);
      vars.url_exception_cache.setNodeDeleteTimeout(settings.node_delete_timeout);
    };
    const request_url = this._SERVER_HOST + '/s';
    this._startJsonRequest(this._update_settings_xhr, request_url, request_data, response_callback);
  },

  _verifyUrls: function(verification_complete_callback) {
    const vars = this._vars;
    const urls = this._getDictionaryKeys(vars.unverified_urls);
    const url_exceptions = this._getDictionaryKeys(vars.unverified_url_exceptions);

    // sort urls and url_exceptions in order to achieve better compression.
    urls.sort();
    url_exceptions.sort();

    const request_data = [
        compressStrings(urls),
        compressStrings(url_exceptions),
    ];
    vars.unverified_urls = {};
    vars.unverified_url_exceptions = {};

    const that = this;
    const response_callback = function(response) {
      that._updateCache(
          response[0],
          urls,
          vars.url_cache,
          urlValueConstructor,
          defaultUrlValue);
      that._updateCache(
          response[1],
          url_exceptions,
          vars.url_exception_cache,
          urlExceptionValueConstructor,
          defaultUrlExceptionValue);
      that._cleanupUnverifiedUrls(vars.unverified_urls, vars.url_cache);
      that._cleanupUnverifiedUrls(vars.unverified_url_exceptions, vars.url_exception_cache);
    };
    const request_url = this._SERVER_HOST + '/g';
    this._startJsonRequest(this._verify_urls_xhr, request_url, request_data, response_callback, verification_complete_callback);
  },

  _isUnverifiedUrlsEmpty: function() {
    const vars = this._vars;
    for (url in vars.unverified_urls) {
      return false;
    }
    for (url in vars.unverified_url_exceptions) {
      return false;
    }
    return true;
  },

  _launchUrlVerifier: function() {
    const vars = this._vars;
    if (vars.is_url_verifier_active || this._isUnverifiedUrlsEmpty()) {
      return;
    }
    logging.info('url verifier started');
    vars.is_url_verifier_active = true;
    const that = this;
    const verification_complete_callback = function() {
      logging.info('url verifier stopped');
      vars.is_url_verifier_active = false;
      that._launchUrlVerifier();
    };
    const verify_urls_callback = function() {
      that._verifyUrls(verification_complete_callback);
    };
    this._executeDelayed(this._verify_urls_timer, verify_urls_callback, this._settings.url_verifier_delay);
  },

  _isStaleCacheNode: function(cache_node) {
    return (this._vars.current_date - cache_node.last_check_date > this._settings.stale_node_timeout);
  },

  _getCacheValue: function(cache, unverified_urls, url, max_url_length) {
    const cache_node = cache.get(url, this._vars.current_date);
    if (this._isStaleCacheNode(cache_node)) {
      url = url.substring(0, max_url_length);
      unverified_urls[url] = true;
      this._launchUrlVerifier();
    }
    return cache_node.value;
  },

  _getUrlValue: function(url) {
    const vars = this._vars;
    return this._getCacheValue(vars.url_cache, vars.unverified_urls, url, this._settings.max_url_length);
  },

  _getUrlExceptionValue: function(url) {
    const vars = this._vars;
    return this._getCacheValue(vars.url_exception_cache, vars.unverified_url_exceptions, url, this._settings.max_url_exception_length);
  },

  _isIp: function(host_parts) {
    if (host_parts[0].indexOf(':') != -1) {
      // IPv6 address
      return true;
    }
    if (host_parts.length == 4) {
      let part, int_part;
      for (let i = 0; i < 4; i++) {
        part = host_parts[i];
        int_part = parseInt(part);
        if (int_part != part || int_part < 0 || int_part > 255) {
          return false;
        }
      }
      // IPv4 address
      return true;
    }
    return false;
  },

  _getCanonicalUrl: function(content_location) {
    content_location = content_location.clone();

    // reverse domain parts if this is not an IP
    const host_parts = content_location.host.split('.');
    if (!this._isIp(host_parts)) {
      content_location.host = host_parts.reverse().join('.');
    }
    content_location.userPass = '';

    // Use dummy scheme, which will be removed later.
    content_location.scheme = 'http';
    // remove dummy scheme and lowercase the url
    return content_location.spec.substring(7).toLowerCase();
  },

  _matchesRegexp: function(reg_exp, s) {
    if (!reg_exp) {
      return false;
    }
    return (s.search(reg_exp) != -1);
  },

  _verifyLocation: function(content_location, request_origin) {
    if (!this._shouldProcessUri(content_location)) {
      return true;
    }
    const content_location_url = this._getCanonicalUrl(content_location);
    const url_value = this._getUrlValue(content_location_url);
    let is_whitelist = url_value.is_whitelist;

    let request_origin_url;
    if (request_origin && this._shouldProcessUri(request_origin)) {
      request_origin_url = this._getCanonicalUrl(request_origin);

      // override is_whitelist by per-site exception value if required.
      const url_exception_value = this._getUrlExceptionValue(request_origin_url);
      if (this._matchesRegexp(url_exception_value.whitelisted_canonical_urls, content_location_url)) {
        logging.info('the content_location_url=[%s] is whitelisted via url exceptions for request_origin_url=[%s]', content_location_url, request_origin_url);
        is_whitelist = true;
      }
      else if (this._matchesRegexp(url_exception_value.blacklisted_canonical_urls, content_location_url)) {
        logging.info('the content_location_url=[%s] is blacklisted via url exceptions for request_origin_url=[%s]', content_location_url, request_origin_url);
        is_whitelist = false;
      }
    }

    logging.info('is_whitelist=[%s], original=[%s], conten_location_url=[%s], request_origin_url=[%s]', is_whitelist, content_location.spec, content_location_url, request_origin_url);
    return is_whitelist;
  },
};

// XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
// XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
if (XPCOMUtils.generateNSGetFactory) {
  const NSGetFactory = XPCOMUtils.generateNSGetFactory([AdBan]);
}
else {
  const NSGetModule = XPCOMUtils.generateNSGetModule([AdBan]);
}

