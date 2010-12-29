const Cu = Components.utils;
const Ci = Components.interfaces;
const Cc = Components.classes;
const Cr = Components.results;

Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import('resource://gre/modules/XPCOMUtils.jsm');

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

    // delete TODO nodes for the given node.
    const children = node.children;
    for (let c in children) {
      node = children[c];
      if ('value' in node && node.last_check_date == 0) {
        delete node.value;
        delete node.last_check_date;
      }
    }
  },
  _get: function(key_chars, current_date) {
    const key_length = key_chars.length;
    let node = this._root;
    let node_with_value = node;
    let node_depth = 0;
    let tmp_node, c;
    while (node_depth < key_length) {
      c = key_chars[node_depth];
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
  _add: function(key_chars, value, current_date) {
    const key_length = key_chars.length;
    const tmp = this._get(key_chars, current_date);
    let node = tmp[0];
    let node_depth = tmp[2];
    let new_node, c;
    while (node_depth < key_length) {
      c = key_chars[node_depth];
      new_node = this._createNode();
      node.children[c] = new_node;
      node = new_node;
      node_depth++;
    }
    node.value = value;
    node.last_check_date = current_date;
  },
  _clearNodesWithValue: function(node, node_depth, end_key) {
    const end_key_chars = end_key.split('');
    const end_key_length = end_key_chars.length;
    let tmp_node, c;
    while (node_depth < end_key_length) {
      c = end_key_chars[node_depth];
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
    const key_chars = key.split('');
    return this._get(key_chars, current_date)[1];
  },
  add: function(key, value, current_date) {
    const key_chars = key.split('');
    this._add(key_chars, value, current_date);
  },
  update: function(start_key, end_keys, value, current_date) {
    const start_key_chars = start_key.split('');
    const tmp = this._get(start_key_chars, current_date);
    const node = tmp[0];
    const node_depth = tmp[2];
    if (node_depth == start_key_chars.length) {
      const end_keys_length = end_keys.length;
      for (let i = 0; i < end_keys_length; i++) {
        this._clearNodesWithValue(node, node_depth, end_keys[i]);
      }
    }
    this._add(start_key_chars, value, current_date);
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

const createUrlCacheDefaultValue = function() {
  return {
      is_whitelist: true,
  };
};

const createUrlExceptionCacheDefaultValue = function() {
  return {
      blacklisted_canonical_urls: [],
      whitelisted_canonical_urls: [],
      css_selectors: [],
  };
};

const createEmptyUrlCache = function(node_delete_timeout) {
  return new Trie(createUrlCacheDefaultValue(), node_delete_timeout);
};

const createEmptyUrlExceptionCache = function(node_delete_timeout) {
  return new Trie(createUrlExceptionCacheDefaultValue(), node_delete_timeout);
};

const stringsToRegExps = function(s_list) {
  const regexp_list = [];
  const s_list_length = s_list.length;
  for (let i = 0; i < s_list_length; i++) {
    regexp_list[i] = new RegExp(s_list[i]);
  }
  return regexp_list;
};

const regExpsToStrings = function(regexp_list) {
  const s_list = [];
  const regexp_list_length = regexp_list.length;
  for (let i = 0; i < regexp_list_length; i++) {
    s_list[i] = regexp_list[i].source;
  }
  return s_list;
};

const BLACKLISTED_CANONICAL_URLS_BIT_MASK = (1 << 0);
const WHITELISTED_CANONICAL_URLS_BIT_MASK = (1 << 1);
const CSS_SELECTORS_BIT_MASK = (1 << 2);

const urlNodeConstructor = function(v) {
  return (v.is_whitelist + 0);
};

const urlExceptionNodeConstructor = function(v) {
  const blacklisted_canonical_urls = regExpsToStrings(v.blacklisted_canonical_urls);
  const whitelisted_canonical_urls = regExpsToStrings(v.whitelisted_canonical_urls);
  const css_selectors = v.css_selectors;

  let d_bitmap = 0;
  const d = [];
  if (blacklisted_canonical_urls.length > 0) {
    d_bitmap |= BLACKLISTED_CANONICAL_URLS_BIT_MASK;
    d.push(blacklisted_canonical_urls);
  }
  if (whitelisted_canonical_urls.length > 0) {
    d_bitmap |= WHITELISTED_CANONICAL_URLS_BIT_MASK;
    d.push(whitelisted_canonical_urls);
  }
  if (css_selectors.length > 0) {
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
  let blacklisted_canonical_urls = [];
  let whitelisted_canonical_urls = [];
  let css_selectors = [];

  const d_bitmap = d.pop();
  let i = 0;
  if (d_bitmap & BLACKLISTED_CANONICAL_URLS_BIT_MASK) {
    blacklisted_canonical_urls = stringsToRegExps(d[i]);
    i++;
  }
  if (d_bitmap & WHITELISTED_CANONICAL_URLS_BIT_MASK) {
    whitelisted_canonical_urls = stringsToRegExps(d[i]);
    i++;
  }
  if (d_bitmap & CSS_SELECTORS_BIT_MASK) {
    css_selectors = d[i];
    i++;
  }
  return {
      blacklisted_canonical_urls: blacklisted_canonical_urls,
      whitelisted_canonical_urls: whitelisted_canonical_urls,
      css_selectors: css_selectors,
  };
};

const adban = function() {
  // allow direct access to the XPCOM object from javascript.
  // see https://developer.mozilla.org/en/wrappedJSObject .
  this.wrappedJSObject = this;
};

adban.prototype = {
  // this shit is for XPCOM
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
  _REJECT_EXCEPTION: Components.results.NS_BASE_STREAM_WOULD_BLOCK,
  _DATA_DIRECTORY_NAME: 'adban',
  _CACHE_FILENAME: 'cache.json',
  _FILTERED_SCHEMES: {
      http: true,
      https: true,
      ftp: true,
  },
  _SERVER_HOST: 'https://ad-ban-dev.appspot.com',
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
  _complaint_report_xhr: Cc['@mozilla.org/xmlextras/xmlhttprequest;1'].createInstance(Ci.nsIXMLHttpRequest),
  _json_encoder: Cc['@mozilla.org/dom/json;1'].createInstance(Ci.nsIJSON),
  _converter: Cc['@mozilla.org/intl/scriptableunicodeconverter'].createInstance(Ci.nsIScriptableUnicodeConverter),
  _category_manager: Cc['@mozilla.org/categorymanager;1'].getService(Ci.nsICategoryManager),
  _window_mediator: Cc['@mozilla.org/appshell/window-mediator;1'].getService(Ci.nsIWindowMediator),
  _directory_service: Cc['@mozilla.org/file/directory_service;1'].getService(Ci.nsIProperties),
  _io_service: Cc['@mozilla.org/network/io-service;1'].getService(Ci.nsIIOService),
  _observer_service: Cc['@mozilla.org/observer-service;1'].getService(Ci.nsIObserverService),
  _main_thread: Cc['@mozilla.org/thread-manager;1'].getService().mainThread,
  _verify_urls_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _file_writer_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _update_current_date_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _update_settings_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),

  // component's settings. New values for these settings are periodically read
  // from the server.
  _settings: {
    url_verifier_delay: 1000,
    file_writer_interval: 1000 * 60 * 10,
    stale_node_timeout: 1000 * 3600 * 24,
    node_delete_timeout: 1000 * 3600 * 24 * 30,
    current_date_granularity: 1000 * 60 * 5,
    update_settings_interval: 1000 * 10,

    import: function(data) {
      this.url_verifier_delay = data[0];
      this.file_writer_interval = data[1];
      this.stale_node_timeout = data[2];
      this.node_delete_timeout = data[3];
      this.current_date_granularity = data[4];
      this.update_settings_interval = data[5];
    },

    export: function() {
      return [
          this.url_verifier_delay,
          this.file_writer_interval,
          this.stale_node_timeout,
          this.node_delete_timeout,
          this.current_date_granularity,
          this.update_settings_interval,
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
    current_date: (new Date()).getTime(),
    auth_token: '',
    url_cache: createEmptyUrlCache(0),
    url_exception_cache: createEmptyUrlExceptionCache(0),
    unverified_urls: {},
    unverified_url_exceptions: {},
    opened_popups: {},
    is_url_verifier_active: false,
    is_cache_saver_active: false,
    is_active: false,
    is_in_private_mode: false,
  },

  _state_listeners: {},
  _last_state_listener_id: 0,

  // net-channel-event-sinks category event handler
  onChannelRedirect: function(old_channel, new_channel, flags) {
    dump('redirect from [' + old_channel.URI.spec + '] to  [' + new_channel.URI.spec + ']\n');

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
    callback(Cr.NS_OK);
  },

  // content-policy category event handler
  shouldLoad: function(content_type, content_location, request_origin, node, mime_type, extra) {
    if (this._verifyLocation(content_location, request_origin)) {
      return this._ACCEPT;
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
      const doc = e.target;
      if (doc.location.href == this._getLoginUrl()) {
        const cookie = doc.cookie;
        dump('login page captured. cookie=['+cookie+']\n');
        this._readAuthTokenFromCookie(cookie);
      }
      this._injectCssToDocument(e.target);
    }
  },

  // nsIObserver implementation
  observe: function(subject, topic, data) {
    const observer_service = this._observer_service;
    const vars = this._vars;
    if (topic == 'app-startup') {
      dump('app-startup\n');
      // perform initialization at 'profile-after-change' step,
      // which is the only available in FF4.
      // See https://developer.mozilla.org/en/XPCOM/XPCOM_changes_in_Gecko_2.0 .
      observer_service.addObserver(this, 'profile-after-change', false);
    }
    else if (topic == 'profile-after-change') {
      dump('profile-after-change\n');
      observer_service.addObserver(this, 'quit-application', false);
      observer_service.addObserver(this, 'private-browsing', false);
      try {
        const private_browsing_service = Cc['@mozilla.org/privatebrowsing;1'].getService(Ci.nsIPrivateBrowsingService);
        if (private_browsing_service.privateBrowsingEnabled) {
          vars.is_in_private_mode = true;
        }
      }
      catch (e) {
        dump('it seems the browser doesn\'t support private browsing\n');
      }
      this._converter.charset = 'UTF-8';
      this._loadCaches();
      this.start();
    }
    else if (topic == 'private-browsing') {
      dump('private-browsing: ['+data+']\n');
      if (data == 'enter') {
        vars.is_in_private_mode = true;
      }
      else if (data == 'exit') {
        this._loadCaches();
        vars.is_in_private_mode = false;
      }
    }
    else if (topic == 'quit-application') {
      dump('quit-application\n');
      this.stop();
      this._flushCaches();
      observer_service.removeObserver(this, 'private-browsing');
      observer_service.removeObserver(this, 'profile-after-change');
      observer_service.removeObserver(this, 'quit-application');
    }
  },

  // publicly accessed methods.
  start: function() {
    const vars = this._vars;
    if (vars.is_active) {
      return;
    }
    const category_manager = this._category_manager;
    category_manager.addCategoryEntry('content-policy', this.classDescription, this.contractID, false, false);
    category_manager.addCategoryEntry('net-channel-event-sinks', this.classDescription, this.contractID, false, false);
    this._startTimers();
    vars.is_active = true;
    this._notifyStateListeners(true);
    dump('AdBan component has been started\n');
  },

  stop: function() {
    const vars = this._vars;
    if (!vars.is_active) {
      return;
    }
    this._stopTimers();
    const category_manager = this._category_manager;
    category_manager.deleteCategoryEntry('net-channel-event-sinks', this.classDescription, false);
    category_manager.deleteCategoryEntry('content-policy', this.classDescription, false);
    vars.is_active = false;
    this._notifyStateListeners(false);
    dump('AdBan component has been stopped\n');
  },

  complaint_report: function(site_url, comment, success_callback) {
    const request_data = [site_url, comment];
    const request_url = this._SERVER_HOST + '/c';

    const response_callback = function() {
      success_callback();
    };
    this._startJsonRequest(this._complaint_report_xhr, request_url, request_data, response_callback);
  },

  getHelpUrl: function() {
    return this._SERVER_HOST + '/ff/help';
  },

  getFirstRunUrl: function() {
    return this._SERVER_HOST + '/ff/first_run';
  },

  subscribeToStateChange: function(state_change_callback) {
    const listener_id = this._last_state_listener_id++;
    this._state_listeners[listener_id] = state_change_callback;
    state_change_callback(this._vars.is_active);
    return listener_id;
  },

  unsubscribeFromStateChange: function(listener_id) {
    delete this._state_listeners[listener_id];
  },

  _notifyStateListeners: function(is_active) {
    const state_listeners = this._state_listeners;
    for (let listener_id in state_listeners) {
      dump('notifying listener ['+listener_id+']\n');
      state_listeners[listener_id](is_active);
    }
  },

  // private methods.
  _readAuthTokenFromCookie: function(cookie) {
    const cookies = cookie.split(/;\s*/);
    const cookies_length = cookies.length;
    let cookie_pair;
    for (let i = 0; i < cookies_length; i++) {
      cookie_pair = cookies[i].split('=');
      if (cookie_pair[0] == 'a') {
        const auth_token = cookie_pair[1];
        dump('auth_token obtained from cookie=['+auth_token+']\n');
        this._vars.auth_token = auth_token;
        return;
      }
    }
    dump('cannot find auth token');
  },

  _getLoginUrl: function() {
    // optimize the login url construction, since it is called in hot paths
    // (see for example, handleEvent()).
    let login_url = this._LOGIN_URL;
    if (!login_url) {
      login_url = this._LOGIN_URL = this._SERVER_HOST + '/ff/login';
    }
    return login_url;
  },

  _startRepeatingTimer: function(timer, callback, interval) {
    const timer_callback = {
        notify: callback,
    };
    timer.initWithCallback(timer_callback, interval, timer.TYPE_REPEATING_SLACK);
  },

  _startTimers: function() {
    const that = this;
    const settings = this._settings;

    // it is safe re-initializing timers in-place -
    // in this case the first callback will be automatically canceled.
    // See https://developer.mozilla.org/En/nsITimer .
    this._startRepeatingTimer(
        this._file_writer_timer,
        function() { that._saveCaches(); },
        settings.file_writer_interval);

    const update_current_date_callback = function() {
      that._vars.current_date = (new Date()).getTime();
    };
    update_current_date_callback();
    this._startRepeatingTimer(
        this._update_current_date_timer,
        update_current_date_callback,
        settings.current_date_granularity);

    this._startRepeatingTimer(
        this._update_settings_timer,
        function() { that._updateSettings(); },
        settings.update_settings_interval);
  },

  _stopTimers: function() {
    // canceled timers can be re-used later.
    // See https://developer.mozilla.org/En/nsITimer#cancel() .
    this._file_writer_timer.cancel();
    this._update_current_date_timer.cancel();
    this._update_settings_timer.cancel();
  },

  _createUri: function(url) {
    // TODO: verify if url contains non-ascii chars.
    return this._io_service.newURI(url, null, null);
  },

  _getRequestOriginFromChannel: function(channel) {
    // I don't know how this code works. It has been copy-pasted from
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
      catch (e) {
        // It looks like css channels don't provide nsIDOMWindow
        // during redirects. Just silently skip this, because it is unclear
        // how to determine the request_origin in this case.
      }
    }
    return request_origin;
  },

  _runInMainThread: function(callback) {
    const main_event = {
        run: callback,
    };
    const main_thread = this._main_thread;
    main_thread.dispatch(main_event, main_thread.DISPATCH_NORMAL);
  },

  _getDataDirectory: function() {
    const data_dir = this._directory_service.get('ProfD', Ci.nsIFile);
    data_dir.append(this._DATA_DIRECTORY_NAME);
    if (!data_dir.exists() || !data_dir.isDirectory()) {
      data_dir.create(data_dir.DIRECTORY_TYPE, 0774);
    }
    return data_dir;
  },

  _getFileForCaches: function() {
    const file = this._getDataDirectory().clone();
    file.append(this._CACHE_FILENAME);
    return file;
  },

  _readFromFile: function(file, read_complete_callback) {
    if (!file.exists()) {
      dump('the file ['+file.path+'] doesn\'t exist, skipping loading from file\n');
      return;
    }
    const ios = this._io_service;
    const fileURI = ios.newFileURI(file);
    const channel = ios.newChannelFromURI(fileURI);
    const that = this;
    const observer = {
        onStreamComplete : function(loader, context, status, length, result) {
          if (!Components.isSuccessCode(status)) {
            dump('error when reading the file=['+file.path+'], status=['+status+']\n');
            return;
          }
          const data = that._converter.convertFromByteArray(result, length);
          read_complete_callback(data);
        }
    };
    const stream_loader = Cc['@mozilla.org/network/stream-loader;1'].createInstance(Ci.nsIStreamLoader);
    stream_loader.init(observer);
    channel.asyncOpen(stream_loader, null);
  },

  _writeToFile: function(file, data, write_complete_callback) {
    const input_stream = this._converter.convertToInputStream(data);
    const output_stream = Cc['@mozilla.org/network/file-output-stream;1'].createInstance(Ci.nsIFileOutputStream);
    output_stream.init(file, -1, -1, 0);
    const async_copy_callback = function(status) {
      const is_success = Components.isSuccessCode(status);
      if (!is_success) {
        dump('error when writing to file=['+file.path+'], status=['+status+']\n');
      }
      if (write_complete_callback) {
        write_complete_callback(is_success);
      }
    };
    NetUtil.asyncCopy(input_stream, output_stream, async_copy_callback);
  },

  _flushCaches: function() {
    const vars = this._vars;
    const node_delete_timeout = this._settings.node_delete_timeout;
    vars.url_cache = createEmptyUrlCache(node_delete_timeout);
    vars.url_exception_cache = createEmptyUrlExceptionCache(node_delete_timeout);
  },

  _loadCaches: function() {
    // create empty caches, so the component can work with them until the
    // real data will be asynchronously loaded later.
    this._flushCaches();

    const that = this;
    const vars = this._vars;
    const node_delete_timeout = this._settings.node_delete_timeout;
    const file = this._getFileForCaches();
    const read_complete_callback = function(json_data) {
      const data = that._json_encoder.decode(json_data);
      vars.auth_token = data[0];
      that._settings.import(data[1]);
      const url_cache = Trie.importFromNodes(
          createUrlCacheDefaultValue(),
          node_delete_timeout,
          data[2],
          urlValueConstructor);
      const url_exception_cache = Trie.importFromNodes(
          createUrlExceptionCacheDefaultValue(),
          node_delete_timeout,
          data[3],
          urlExceptionValueConstructor);
      vars.url_cache = url_cache;
      vars.url_exception_cache = url_exception_cache;
    };
    this._readFromFile(file, read_complete_callback);
  },

  _saveCaches: function() {
    const vars = this._vars;
    if (vars.is_in_private_mode) {
      dump('don\'t save caches in private mode\n');
      return;
    }
    if (vars.is_cache_saver_active) {
      dump('previos cache saving operation isn\'t complete yet\n');
      return;
    }
    vars.is_cache_saver_active = true;
    const settings = this._settings;
    const current_date = vars.current_date;
    const url_cache = vars.url_cache;
    const url_exception_cache = vars.url_exception_cache;
    const data = [
        vars.auth_token,
        settings.export(),
        url_cache.exportToNodes(urlNodeConstructor, current_date),
        url_exception_cache.exportToNodes(urlExceptionNodeConstructor, current_date),
    ]
    const json_data = this._json_encoder.encode(data);
    const file = this._getFileForCaches();
    const write_complete_callback = function() {
      vars.is_cache_saver_active = false;
    };
    this._writeToFile(file, json_data, write_complete_callback);
  },

  _injectCssToDocument: function(doc) {
    const site_url = this._createUri(doc.location.href);
    if (!(site_url.scheme in this._FILTERED_SCHEMES)) {
      return;
    }

    const canonical_site_url = this._getCanonicalUrl(site_url);
    const url_exception_value = this._getUrlExceptionValue(canonical_site_url);
    const css_selectors = url_exception_value.css_selectors;

    if (css_selectors.length > 0) {
      const s = doc.createElement('style');
      s.type = 'text/css';
      s.innerHTML = css_selectors.join(',') + '{display: none !important;}';
      dump('adding css selector=['+s.innerHTML+']\n');
      doc.getElementsByTagName('head')[0].appendChild(s);
    }
  },

  _updateUrlCache: function(response_data, urls) {
    const vars = this._vars;
    const url_cache = vars.url_cache;
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
      let value = urlValueConstructor(properties);
      url_cache.update(url, end_urls, value, vars.current_date);

      const todo_chars = todo.split('');
      const todo_length = todo_chars.length;
      for (let j = 0; j < todo_length; j++) {
        // value must be created each time it is added into url_cache,
        // otherwise a single modification of the value will modify other
        // values.
        value = createUrlCacheDefaultValue();
        url_cache.add(url + todo_chars[j], value, 0);
      }
    }
  },

  _updateUrlExceptionCache: function(response_data, url_exceptions) {
    const vars = this._vars;
    const url_exception_cache = vars.url_exception_cache;
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
        end_urls[j] = url_exceptions[url_idx[j]];
      }
      const url = url_exceptions[url_idx[0]].substring(0, url_length);
      let value = urlExceptionValueConstructor(properties);
      url_exception_cache.update(url, end_urls, value, vars.current_date);

      const todo_chars = todo.split('');
      const todo_length = todo_chars.length;
      for (let j = 0; j < todo_length; j++) {
        // value must be created each time it is added into url_exception_cache,
        // otherwise a single modification of the value will modify other
        // values.
        value = createUrlExceptionCacheDefaultValue();
        url_exception_cache.add(url + todo_chars[j], value, 0);
      }
    }
  },

  _getDictionaryKeys: function(dict) {
    const keys = [];
    for (let key in dict) {
      keys.push(key);
    }
    return keys;
  },

  _cleanupUnverifiedUrls: function() {
    const vars = this._vars;
    const unverified_urls = vars.unverified_urls;
    const urls = this._getDictionaryKeys(unverified_urls);
    const url_cache = vars.url_cache;
    for (let i = 0; i < urls.length; i++) {
      const url = urls[i];
      const cache_node = url_cache.get(url, vars.current_date);
      if (!this._isStaleCacheNode(cache_node)) {
        dump('the url [' + url + '] is already verified\n');
        delete unverified_urls[url];
      }
    }
  },

  _cleanupUnverifiedUrlExceptions: function() {
    const vars = this._vars;
    const unverified_url_exceptions = vars.unverified_url_exceptions;
    const urls = this._getDictionaryKeys(unverified_url_exceptions);
    const url_exception_cache = vars.url_exception_cache;
    for (let i = 0; i < urls.length; i++) {
      const url = urls[i];
      const cache_node = url_exception_cache.get(url, vars.current_date);
      if (!this._isStaleCacheNode(cache_node)) {
        dump('the url [' + url + '] is already verified\n');
        delete unverified_url_exceptions[url];
      }
    }
  },

  _openPopupInternal: function(url) {
    const opened_popups = this._vars.opened_popups;
    const popup_window = opened_popups[url];
    if (popup_window && !popup_window.closed) {
      dump('popup window for url=['+url+'] is already opened\n');
      popup_window.focus();
      return;
    }

    const browser_window = this._window_mediator.getMostRecentWindow('navigator:browser');
    if (!browser_window) {
      dump('there are no browser windows');
      return;
    }

    // create fake popup window object in order to prevent race condition:
    // the window.open() is called the second time before the main thread
    // is dispatched to assign the first popup window to opened_popups[url].
    opened_popups[url] = {
        closed: false,
        focus: function() {},
    };

    try {
      // TODO: modal and alwaysRaised attributes don't work on the popup. Investigate this.
      opened_popups[url] = browser_window.open(url, 'adban-popup-' + url, 'alwaysRaised');
    }
    catch (e) {
      delete opened_popups[url];
    }
  },

  _openPopup: function(url) {
    // defer execution of the openPopupInternal(), since it seems it can block
    // or interact badly when called from certain contexts such as
    // shouldLoad() or onChannelRedirect() event handlers.
    const that = this;
    const defer_callback = function() {
      that._openPopupInternal(url);
    };
    this._runInMainThread(defer_callback);
  },

  _showLoginPage: function() {
    // login screen must be displayed for this user.
    // if the user isn't authorized, then the login screen must redirect
    // to the landing page, where the reason for the authorization error
    // must be displayed.
    this._openPopup(this._getLoginUrl());
  },

  _processJsonResponse: function(request_text, response_text, response_callback) {
    const error_codes = this._ERROR_CODES;
    const vars = this._vars;

    dump('response_text=['+response_text+']\n');
    const response_data = this._json_encoder.decode(response_text);
    const error_code = response_data[0];
    if (error_code == error_codes.NO_ERRORS) {
      if (response_callback) {
        response_callback(response_data[1]);
      }
    }
    else if (error_code == error_codes.AUTHENTICATION_ERROR ||
             error_code == error_codes.AUTHORIZATION_ERROR) {
      dump('authentication or authorization failed for auth_token=['+vars.auth_token+']. error_code='+error_code+'\n');
      vars.auth_token = '';
    }
    else {
      dump('server responded with the error_code='+error_code+' for the request_text=['+request_text+']. response_text=['+response_text+']\n');
    }
  },

  _startJsonRequest: function(xhr, request_url, request_data, response_callback, finish_callback) {
    const auth_token = this._vars.auth_token;
    if (auth_token == '') {
      dump('the user must be authenticated\n');
      this._showLoginPage();
      if (finish_callback) {
        finish_callback();
      }
      return;
    };

    const request_text = this._json_encoder.encode([auth_token, request_data]);
    dump('request_url=['+request_url+'], request_text=[' + request_text + ']\n');

    const that = this;
    xhr.open('POST', request_url);
    xhr.onreadystatechange = function() {
      if (xhr.readyState == 4) {
        try {
          const http_status = xhr.status;
          if (http_status == 200) {
            that._processJsonResponse(request_text, xhr.responseText, response_callback);
          }
          else {
            dump('unexpected HTTP status code for the request_url=['+request_url+'], request_text=['+request_text+'], http_status=['+http_status+']\n');
          }
        }
        finally {
          if (finish_callback) {
            finish_callback();
          }
        }
      }
    };
    const encoded_request = encodeURIComponent(request_text);
    xhr.send(encoded_request);
  },

  _updateSettings: function() {
    const request_data = [];
    const settings = this._settings;
    const vars = this._vars;
    const that = this;
    const response_callback = function(response) {
      settings.import(response);
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
      that._updateUrlCache(response[0], urls);
      that._updateUrlExceptionCache(response[1], url_exceptions);
      that._cleanupUnverifiedUrls();
      that._cleanupUnverifiedUrlExceptions();
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
    dump('!!!!url verifier started\n');
    vars.is_url_verifier_active = true;
    const that = this;
    const verification_complete_callback = function() {
      dump('!!!!url verifier stopped\n');
      vars.is_url_verifier_active = false;
      that._launchUrlVerifier();
    };
    const verify_urls_timer_callback = {
        notify: function() {
          that._verifyUrls(verification_complete_callback);
        },
    };
    const verify_urls_timer = this._verify_urls_timer;
    verify_urls_timer.initWithCallback(
        verify_urls_timer_callback,
        this._settings.url_verifier_delay,
        verify_urls_timer.TYPE_ONE_SHOT);
  },

  _isStaleCacheNode: function(cache_node) {
    return (this._vars.current_date - cache_node.last_check_date > this._settings.stale_node_timeout);
  },

  _getUrlValue: function(url) {
    const vars = this._vars;
    const cache_node = vars.url_cache.get(url, vars.current_date);
    if (this._isStaleCacheNode(cache_node)) {
      vars.unverified_urls[url] = true;
      this._launchUrlVerifier();
    }
    return cache_node.value;
  },

  _getUrlExceptionValue: function(url) {
    const vars = this._vars;
    const cache_node = vars.url_exception_cache.get(url, vars.current_date);
    if (this._isStaleCacheNode(cache_node)) {
      vars.unverified_url_exceptions[url] = true;
      this._launchUrlVerifier();
    }
    return cache_node.value;
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

  _matchesRegexp: function(regexp_list, s) {
    const regexp_list_length = regexp_list.length;
    for (let i = 0; i < regexp_list_length; i++) {
      if (s.search(regexp_list[i]) != -1) {
        return true;
      }
    }
    return false;
  },

  _verifyLocation: function(content_location, request_origin) {
    if (!(content_location.scheme in this._FILTERED_SCHEMES)) {
      return true;
    }
    const content_location_url = this._getCanonicalUrl(content_location);
    const url_value = this._getUrlValue(content_location_url);
    let is_whitelist = url_value.is_whitelist;

    let request_origin_url;
    if (request_origin && (request_origin.scheme in this._FILTERED_SCHEMES)) {
      request_origin_url = this._getCanonicalUrl(request_origin);

      // override is_whitelist by per-site exception value if required.
      const url_exception_value = this._getUrlExceptionValue(request_origin_url);
      if (this._matchesRegexp(url_exception_value.whitelisted_canonical_urls, content_location_url)) {
        is_whitelist = true;
      }
      else if (this._matchesRegexp(url_exception_value.blacklisted_canonical_urls, content_location_url)) {
        is_whitelist = false;
      }
    }

    dump('is_whitelist='+is_whitelist+', original=['+content_location.spec+'], content_location_url=['+content_location_url+'], request_origin_url=['+request_origin_url+']\n');
    return is_whitelist;
  },
};

// XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
// XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
if (XPCOMUtils.generateNSGetFactory) {
  const NSGetFactory = XPCOMUtils.generateNSGetFactory([adban]);
}
else {
  const NSGetModule = XPCOMUtils.generateNSGetModule([adban]);
}

