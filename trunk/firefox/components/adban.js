// it is safe defining objects in the global scope of the XPCOM component,
// since they aren't visible outside the component.

const Cu = Components.utils;
const Ci = Components.interfaces;
const Cc = Components.classes;
const Cr = Components.results;

Cu.import('resource://gre/modules/XPCOMUtils.jsm');

const ADDON_VERSION = '2.2.0beta1';
const BACKEND_SERVER_DOMAIN = 'ad-ban.appspot.com';
const FRONTEND_SERVER_DOMAIN = 'www.advertban.com';
const BACKEND_SERVER_PROTOCOL = 'https';
const FRONTEND_SERVER_PROTOCOL = 'http';
const EXTENSION_ID = 'adban@ad-ban.appspot.com';
const app_info = Cc['@mozilla.org/xre/app-info;1'].getService(Ci.nsIXULAppInfo);

const getCurrentDate = function() {
  return Date.now();
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
    this.log(this.levels.NONE, 'addon_version=[%s], app: name=[%s], version=[%s], appBuildId=[%s], ID=[%s], vendor=[%s], platformBuildID=[%s], platformVersion=[%s]',
        [null, ADDON_VERSION, app_info.name, app_info.version, app_info.appBuildID, app_info.ID, app_info.vendor, app_info.platformBuildID, app_info.platformVersion]);
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
      this._pending_messages.forEach(function(pending_message) {
        log_stream.writeString(pending_message);
      });
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
    const date_string = (new Date()).toISOString();
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
  const s_list_length = s_list.length;
  for (let i = 0; i < s_list_length; i++) {
    let s = s_list[i];
    let common_prefix_length = getCommonPrefixLength(prev_s, s);
    result.push(
        common_prefix_length,
        s.substring(common_prefix_length));
    prev_s = s;
  }
  return result;
};

const uncompressIndexes = function(compressed_indexes) {
  const uncompressed_indexes = [];
  compressed_indexes.forEach(function(compressed_index) {
    if (typeof(compressed_index) == 'string') {
      let [start_range, end_range] = compressed_index.split('-');
      start_range = parseInt(start_range);
      end_range = parseInt(end_range);
      while (start_range <= end_range) {
        uncompressed_indexes.push(start_range);
        ++start_range;
      }
    }
    else {
      uncompressed_indexes.push(compressed_index);
    }
  });
  return uncompressed_indexes;
};

const Trie = function(root_value) {
  const root = this._createNode();
  root.value = root_value;
  root.last_check_date = 0;
  this._root = root;
  this._stale_node_timeout = 0;
  this._node_delete_timeout = 0;
};

Trie.importFromNodes = function(root_value, stale_node_timeout, node_delete_timeout, nodes, value_constructor) {
  const trie = new Trie(root_value);
  trie.setStaleNodeTimeout(stale_node_timeout);
  trie.setNodeDeleteTimeout(node_delete_timeout);
  const nodes_length = nodes.length;
  let key = '';
  for (let i = 0; i < nodes_length; i++) {
    let [common_prefix_length, key_suffix, value_serialized, last_check_date] = nodes[i];
    key = key.substring(0, common_prefix_length) + key_suffix;
    let value = value_constructor(value_serialized);
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

  _isNodeWithValue: function(node) {
    return ('value' in node);
  },

  _clearNode: function(node, is_parent_node_with_value) {
    delete node.value;
    if (is_parent_node_with_value) {
      node.last_check_date = 0;
    }
    else {
      delete node.last_check_date;
    }

    const children = node.children;
    for (let c in children) {
      node = children[c];
      if (this.isTodoNode(node)) {
        delete node.last_check_date;
      }
    }
  },

  _add: function(node, node_depth, key, value, current_date) {
    const key_length = key.length;
    while (node_depth < key_length) {
      let c = key[node_depth];
      let new_node = this._createNode();
      node.children[c] = new_node;
      node = new_node;
      node_depth++;
    }
    node.last_check_date = current_date;
    if (!this.isTodoNode(node)) {
      node.value = value;
    }
    return node;
  },

  _deleteObsoleteChildren: function(children, node_depth, end_keys) {
    end_keys.forEach(function(end_key) {
      if (node_depth < end_key.length) {
        let c = end_key[node_depth];
        delete children[c];
      }
    });
  },

  _updateTodoChildren: function(children, todo) {
    const children_to_delete = [];
    for (let c in children) {
      if (todo.indexOf(c) == -1) {
        children_to_delete.push(c);
      }
    }
    children_to_delete.forEach(function(c) {
      delete children[c];
    });

    // todo is a string, so it doesn't contain forEach implementation.
    // Apply forEach from Array to the todo string.
    Array.prototype.forEach.call(todo, function(c) {
      let node = children[c];
      if (!node) {
        node = this._createNode();
        children[c] = node;
      }
      else if (this._isNodeWithValue(node)) {
        return;
      }
      node.last_check_date = 0;
    }, this);
  },

  _exportSubtreeNodes: function(ctx, key, node, is_parent_node_with_value) {
    let is_node_with_value = this._isNodeWithValue(node);
    let is_todo_node = this.isTodoNode(node);
    if (is_node_with_value && node != this._root && (ctx.current_date - node.last_check_date > this._node_delete_timeout)) {
      this._clearNode(node, is_parent_node_with_value);
      is_node_with_value = false;
      is_todo_node = is_parent_node_with_value;
    }
    if (is_node_with_value || is_todo_node) {
      const common_prefix_length = getCommonPrefixLength(ctx.prev_key, key);
      const key_suffix = key.substring(common_prefix_length);
      const value = is_node_with_value ? node.value : null;
      const value_serialized = ctx.node_constructor(value);
      ctx.nodes.push([
          common_prefix_length,
          key_suffix,
          value_serialized,
          node.last_check_date,
      ]);
      ctx.prev_key = key;
    }
    const children = node.children;
    for (let c in children) {
      this._exportSubtreeNodes(ctx, key + c, children[c], is_node_with_value);
    }
  },

  isTodoNode: function(node) {
    return (node.last_check_date == 0);
  },

  isStaleNode: function(node, current_date) {
    return (current_date - node.last_check_date > this._stale_node_timeout);
  },

  get: function(key) {
    const key_length = key.length;
    let node = this._root;
    let node_with_value = node;
    let non_empty_node = node;
    let node_depth = 0;
    while (node_depth < key_length) {
      let c = key[node_depth];
      let tmp_node = node.children[c];
      if (!tmp_node) {
        break;
      }
      if (this._isNodeWithValue(tmp_node)) {
        non_empty_node = node_with_value = tmp_node;
      }
      else if (this.isTodoNode(tmp_node)) {
        non_empty_node = tmp_node;
      }
      node_depth++;
      node = tmp_node;
    }
    return [
      node,
      node_with_value,
      non_empty_node,
      node_depth,
    ];
  },

  add: function(key, value, current_date) {
    const tmp = this.get(key);
    const node = tmp[0];
    const node_depth = tmp[3];
    return this._add(node, node_depth, key, value, current_date);
  },

  remove: function(key) {
    const tmp = this.get(key);
    const node = tmp[0];
    const node_depth = tmp[3];
    if (node_depth == key.length) {
      this._clearNode(node, false);
    }
  },

  update: function(start_key, end_keys, value, current_date, todo) {
    const tmp = this.get(start_key);
    const node = tmp[0];
    const node_depth = tmp[3];
    if (node_depth == start_key.length) {
      this._deleteObsoleteChildren(node.children, node_depth, end_keys);
    }

    const added_node = this._add(node, node_depth, start_key, value, current_date);
    this._updateTodoChildren(added_node.children, todo);
  },

  getValue: function(node) {
    return node.value;
  },

  exportToNodes: function(node_constructor, current_date) {
    const nodes = [];
    const ctx = {
      prev_key: '',
      nodes: nodes,
      node_constructor: node_constructor,
      current_date: current_date,
    };
    this._exportSubtreeNodes(ctx, '', this._root, true);
    return nodes;
  },

  setStaleNodeTimeout: function(stale_node_timeout) {
    this._stale_node_timeout = stale_node_timeout;
  },

  setNodeDeleteTimeout: function(node_delete_timeout) {
    this._node_delete_timeout = node_delete_timeout;
  },
};

const defaultUrlValue = {
  is_whitelist: true,
};

const defaultUrlExceptionValue = {
};

const defaultPerSiteWhitelistValue = false;

const createEmptyUrlCache = function() {
  return new Trie(defaultUrlValue);
};

const createEmptyUrlExceptionCache = function() {
  return new Trie(defaultUrlExceptionValue);
};

const createEmptyPerSiteWhitelist = function() {
  return new Trie(defaultPerSiteWhitelistValue);
};

const BLACKLIST_REGEXP_BIT_MASK = (1 << 0);
const WHITELIST_REGEXP_BIT_MASK = (1 << 1);
const CSS_SELECTORS_BIT_MASK = (1 << 2);

const urlNodeConstructor = function(v) {
  if (!v) {
    v = defaultUrlValue;
  }

  const is_whitelist = v.is_whitelist + 0;
  const blacklist_regexp = v.blacklist_regexp;
  const whitelist_regexp = v.whitelist_regexp;

  if (blacklist_regexp || whitelist_regexp) {
    return [
      is_whitelist,
      blacklist_regexp ? blacklist_regexp.source : '',
      whitelist_regexp ? whitelist_regexp.source : '',
    ];
  }

  return is_whitelist;
};

const urlExceptionNodeConstructor = function(v) {
  if (!v) {
    v = defaultUrlExceptionValue;
  }
  const blacklist_regexp = v.blacklist_regexp;
  const whitelist_regexp = v.whitelist_regexp;
  const css_selectors = v.css_selectors;

  let d_bitmap = 0;
  const d = [];
  if (blacklist_regexp) {
    d_bitmap |= BLACKLIST_REGEXP_BIT_MASK;
    d.push(blacklist_regexp.source);
  }
  if (whitelist_regexp) {
    d_bitmap |= WHITELIST_REGEXP_BIT_MASK;
    d.push(whitelist_regexp.source);
  }
  if (css_selectors) {
    d_bitmap |= CSS_SELECTORS_BIT_MASK;
    d.push(css_selectors);
  }
  d.push(d_bitmap);
  return d;
};

const perSiteWhitelistNodeConstructor = function(v) {
  return v + 0;
};

const urlValueConstructor = function(d) {
  const v = {};
  if (typeof(d) == 'number') {
    v.is_whitelist = !!(d & 1);
    return v;
  }

  v.is_whitelist = !!(d[0] & 1);
  const blacklist_regexp = d[1];
  const whitelist_regexp = d[2];
  if (blacklist_regexp) {
    v.blacklist_regexp = new RegExp(blacklist_regexp);
  }
  if (whitelist_regexp) {
    v.whitelist_regexp = new RegExp(whitelist_regexp);
  }
  return v;
};

const urlExceptionValueConstructor = function(d) {
  const v = {};
  const d_bitmap = d.pop();
  let i = 0;
  if (d_bitmap & BLACKLIST_REGEXP_BIT_MASK) {
    v.blacklist_regexp = new RegExp(d[i]);
    i++;
  }
  if (d_bitmap & WHITELIST_REGEXP_BIT_MASK) {
    v.whitelist_regexp = new RegExp(d[i]);
    i++;
  }
  if (d_bitmap & CSS_SELECTORS_BIT_MASK) {
    v.css_selectors = d[i];
    i++;
  }
  return v;
};

const perSiteWhitelistValueConstructor = function(d) {
  return !!d;
};

const AdvertBan = function() {
  logging.info('entering AdvertBan constructor');
  const backend_server_host = BACKEND_SERVER_PROTOCOL + '://' + BACKEND_SERVER_DOMAIN;
  this._SEND_URL_COMPLAINT_ENDPOINT = backend_server_host + '/c/' + ADDON_VERSION;
  this._READ_SETTINGS_ENDPOINT = backend_server_host + '/s/' + ADDON_VERSION;
  this._VERIFY_URLS_ENDPOINT = backend_server_host + '/g/' + ADDON_VERSION;

  const frontend_server_host = FRONTEND_SERVER_PROTOCOL + '://' + FRONTEND_SERVER_DOMAIN;
  this.pref_branch = this._pref_service.getBranch('extensions.' + EXTENSION_ID + '.');
  this.HELP_URL = frontend_server_host + '/ff/help/' + ADDON_VERSION;
  this.DONATE_URL = frontend_server_host + '/ff/donate';
  this.RECOMMEND_URL = frontend_server_host + '/ff/recommend';
  this.REPORT_BUG_URL = 'http://code.google.com/p/ad-ban-extensions/issues/entry';
  this.USER_STATUS_URL = frontend_server_host + '/ff/user_status';

  const funcs = [
    ['shouldLoad', true],
    'observe',
    'start',
    'stop',
    'firstRun',
    'sendUrlComplaint',
    'addPerSiteWhitelist',
    'removePerSiteWhitelist',
    ['hasPerSiteWhitelist', false],
    'subscribeToStateChange',
    'unsubscribeFromStateChange',
    'processDocument',
    'executeDeferred',
    'openTab',
  ];
  this._setupErrorHandlers(funcs);

  // allow direct access to the XPCOM object from javascript.
  // see https://developer.mozilla.org/en/wrappedJSObject .
  this.wrappedJSObject = this;
  logging.info('exiting AdvertBan constructor');
};

AdvertBan.prototype = {
  // XPCOM stuff.
  classDescription: 'AdvertBan XPCOM component',
  classID:          Components.ID('{02f31d71-1c0b-48f3-a3b5-100c18dc771e}'),
  contractID:       '@ad-ban.appspot.com/adban;1',
  _xpcom_categories: [
    {category: 'app-startup', service: true},
  ],
  QueryInterface: XPCOMUtils.generateQI([
      Ci.nsIChannelEventSink,
      Ci.nsIContentPolicy,
      Ci.nsIObserver,
  ]),

  // constants
  _ACCEPT: Ci.nsIContentPolicy.ACCEPT,
  _REJECT: Ci.nsIContentPolicy.REJECT_REQUEST,
  _REJECT_EXCEPTION: Cr.NS_BASE_STREAM_WOULD_BLOCK,
  _DATA_DIRECTORY_NAME: 'adban',
  _SETTINGS_FILENAME: 'settings.json',
  _CACHE_FILENAME: 'cache.json',
  _PER_SITE_WHITELIST_FILENAME: 'per-site-whitelist.json',
  _STALE_URLS_FILENAME: 'stale-urls.json',
  _LOGS_FILENAME: 'log.txt',
  _FILTERED_SCHEMES: {
    http: true,
    https: true,
    ftp: true,
    file: true,
  },
  _COLLAPSABLE_NODES: [
    'img',
    'iframe',
    'embed',
    'a',
  ],
  _AUTH_COOKIE_HOST: FRONTEND_SERVER_DOMAIN,
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
  _delayed_startup_xhr_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _update_settings_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _save_cache_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _save_stale_urls_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),
  _process_stale_urls_timer: Cc['@mozilla.org/timer;1'].createInstance(Ci.nsITimer),

  // this logging must be accessible outside the AdvertBan component.
  logging: logging,

  // component's settings. New values for these settings are periodically read
  // from the server.
  _settings: {
    url_verifier_delay: 1000 * 2,
    stale_node_timeout: 1000 * 3600 * 24,
    node_delete_timeout: 1000 * 3600 * 24 * 30,
    update_settings_interval: 1000 * 3600 * 24,
    max_url_length: 50,
    max_url_exception_length: 50,
    save_cache_interval: 1000 * 60 * 20,
    min_backoff_timeout: 1000,
    max_backoff_timeout: 1000 * 3600 * 24,
    max_urls_per_request: 200,
    max_todo_generation_count: 2,
    save_stale_urls_interval: 1000 * 60 * 30,
    process_stale_urls_interval: 1000 * 3600 * 6,

    // the following values cannot be modified by the server.
    startup_xhr_delay: 1000 * 5,

    _bc_import: function(property_name, value) {
      if (value) {
        this[property_name] = value;
      }
    },

    import: function(data) {
      this.url_verifier_delay = data[0];
      this.stale_node_timeout = data[1];
      this.node_delete_timeout = data[2];
      this._deprecated_current_date_granularity = data[3];
      this.update_settings_interval = data[4];
      this.max_url_length = data[5];
      this.max_url_exception_length = data[6];

      this._bc_import('save_cache_interval', data[7]);
      this._bc_import('min_backoff_timeout', data[8]);
      this._bc_import('max_backoff_timeout', data[9]);
      this._bc_import('max_urls_per_request', data[10]);
      this._bc_import('max_todo_generation_count', data[11]);
      this._bc_import('save_stale_urls_interval', data[12]);
      this._bc_import('process_stale_urls_interval', data[13]);
    },

    export: function() {
      return [
        this.url_verifier_delay,
        this.stale_node_timeout,
        this.node_delete_timeout,
        this._deprecated_current_date_granularity,
        this.update_settings_interval,
        this.max_url_length,
        this.max_url_exception_length,
        this.save_cache_interval,
        this.min_backoff_timeout,
        this.max_backoff_timeout,
        this.max_urls_per_request,
        this.max_todo_generation_count,
        this.save_stale_urls_interval,
        this.process_stale_urls_interval,
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
    auth_token: '',
    url_cache: createEmptyUrlCache(),
    url_exception_cache: createEmptyUrlExceptionCache(),
    per_site_whitelist: createEmptyPerSiteWhitelist(),
    stale_urls: {},
    stale_url_exceptions: {},
    unverified_urls: {},
    unverified_url_exceptions: {},
    todo_nodes: [],
    todo_docs: [],
    todo_popups: [],
    is_url_verifier_active: false,
    is_active: false,
    is_in_private_mode: false,
    is_app_startup_called: false,
  },

  _state_listeners: {},
  _last_state_listener_id: 0,

  // net-channel-event-sinks category event handler
  onChannelRedirect: function(old_channel, new_channel, flags) {
    let is_whitelist;
    try {
      logging.info('redirect from [%s] to [%s]', old_channel.URI.spec, new_channel.URI.spec);

      // there is no need in verifying the old_channel, because it must be
      // already verified by shouldLoad() content-policy handler.
      // So verify only the new_channel.
      // Obtain request_origin from the old_channel, since it should be
      // the same as the request_origin for the new_channel and the new_channel
      // can have no request_origin yet.
      const request_origin = this._getRequestOriginFromChannel(old_channel);
      is_whitelist = this._verifyLocation(new_channel.URI, request_origin)[0];
    }
    catch(e) {
      logging.error('error in the onChannelRedirect(): [%s]', e);
      logging.error('stack trace: [%s]', e.stack);
      throw e;
    }
    if (!is_whitelist) {
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
    const [is_whitelist, is_todo, canonical_url, canonical_site_url] = this._verifyLocation(content_location, request_origin);
    let is_popup = false;
    if (node && content_type == Ci.nsIContentPolicy.TYPE_DOCUMENT) {
      const w = node.contentWindow;
      if (w && w.opener && w.top != w.opener.top) {
        is_popup = true;
      }
    }
    const is_collapsable_node = (!is_popup && node && node.nodeName &&
        (this._COLLAPSABLE_NODES.indexOf(node.nodeName.toLowerCase()) != -1) &&
        content_type != Ci.nsIContentPolicy.TYPE_OBJECT_SUBREQUEST);

    if (is_whitelist) {
      if (is_todo) {
        const vars = this._vars;
        if (is_popup) {
          vars.todo_popups.push([canonical_url, node, 0]);
        }
        else if (is_collapsable_node) {
          vars.todo_nodes.push([canonical_url, canonical_site_url, node, 0]);
        }
      }
      return this._ACCEPT;
    }

    if (is_popup) {
      this._closePopup(node, canonical_url);
    }
    else if (is_collapsable_node) {
      this._hideNode(node);
    }
    return this._REJECT;
  },
  shouldProcess: function(content_type, content_location, request_origin, node, mime_type, extra) {
    return this._ACCEPT;
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
      this._loadPerSiteWhitelistAsync();
      this._loadStaleUrlsAsync();
      this.start();

      const that = this;
      const delayed_startup_xhr_callback = function() {
        that._readSettingsFromServer();
        that._processStaleUrls();
      };
      this._executeDelayed(this._delayed_startup_xhr_timer, delayed_startup_xhr_callback, this._settings.startup_xhr_delay);
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
        // there is no need in calling the this._savePerSiteWhitelistSync() here,
        // since the file containing per-site whitelist is already synchronized
        // via addPerSiteWhitelist() and removePerSiteWhitelist().
        this._saveStaleUrlsSync();
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
        this._loadPerSiteWhitelistAsync();
        this._loadStaleUrlsAsync();
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
      // there is no need in calling the this._savePerSiteWhitelistSync() here,
      // since the file containing per-site whitelist is already synchronized
      // via addPerSiteWhitelist() and removePerSiteWhitelist().
      this._saveStaleUrlsSync();

      observer_service.removeObserver(this, 'private-browsing');
      observer_service.removeObserver(this, 'quit-application');
      if (vars.is_app_startup_called) {
        observer_service.removeObserver(this, 'profile-after-change');
      }
    }
  },

  // public methods.
  start: function() {
    const vars = this._vars;
    if (vars.is_active) {
      logging.warning('AdvertBan component already started');
      return;
    }
    const category_manager = this._category_manager;
    category_manager.addCategoryEntry('content-policy', this.classDescription, this.contractID, false, false);
    category_manager.addCategoryEntry('net-channel-event-sinks', this.classDescription, this.contractID, false, false);
    this._startTimers();
    vars.is_active = true;
    this._notifyStateListeners();
    logging.info('AdvertBan component has been started');
  },

  stop: function() {
    const vars = this._vars;
    if (!vars.is_active) {
      logging.warning('AdvertBan component already stopped');
      return;
    }
    this._stopTimers();
    const category_manager = this._category_manager;
    category_manager.deleteCategoryEntry('net-channel-event-sinks', this.classDescription, false);
    category_manager.deleteCategoryEntry('content-policy', this.classDescription, false);
    vars.is_active = false;
    this._notifyStateListeners();
    logging.info('AdvertBan component has been stopped');
  },

  isActive: function() {
    return this._vars.is_active;
  },

  firstRun: function() {
    logging.info('AdvertBan.firstRun()');
  },

  sendUrlComplaint: function(site_url, referer_url, comment, success_callback, failure_callback) {
    logging.info('sending url complaint for site_url=[%s], referer_url=[%s], comment=[%s]', site_url, referer_url, comment);
    const request_data = [
      site_url,
      comment,
      referer_url,
    ];
    const response_callback = function() {
      success_callback();
    };
    const finish_callback = function(error_message) {
      if (error_message) {
        failure_callback(error_message);
      }
    };
    this._startJsonRequest(this._url_complaint_xhr, this._SEND_URL_COMPLAINT_ENDPOINT, request_data, response_callback, finish_callback);
  },

  addPerSiteWhitelist: function(site_url) {
    logging.info('adding per site whitelist for the site_url=[%s]', site_url);
    const canonical_site_host = this._getCanonicalSiteHost(site_url);
    if (!canonical_site_host) {
      return;
    }
    logging.info('adding canonical_site_host=[%s] to the per_site_whitelist', canonical_site_host);
    this._vars.per_site_whitelist.add(canonical_site_host, true, getCurrentDate());
    this._savePerSiteWhitelistSync();
  },

  removePerSiteWhitelist: function(site_url) {
    logging.info('removing per site whitelist for the site_url=[%s]', site_url);
    const canonical_site_host = this._getCanonicalSiteHost(site_url);
    if (!canonical_site_host) {
      return;
    }
    logging.info('removing canonical_site_host=[%s] from the per_site_whitelist', canonical_site_host);
    this._vars.per_site_whitelist.remove(canonical_site_host);
    this._savePerSiteWhitelistSync();
  },

  hasPerSiteWhitelist: function(site_url) {
    logging.info('verifying whether the site with site_url=[%s] is whitelisted', site_url);
    const canonical_site_host = this._getCanonicalSiteHost(site_url);
    if (!canonical_site_host) {
      return null;
    }
    const is_whitelist = this._verifyPerSiteWhitelist(canonical_site_host);
    logging.info('is_whitelist=[%s] for the canonical_site_host=[%s]', is_whitelist, canonical_site_host);
    return is_whitelist;
  },

  subscribeToStateChange: function(state_change_callback) {
    logging.info('subscribing to AdvertBan component state change');
    const listener_id = this._last_state_listener_id++;
    this._state_listeners[listener_id] = state_change_callback;
    return [
      listener_id,
      this._vars.is_active,
    ];
  },

  unsubscribeFromStateChange: function(listener_id) {
    logging.info('unsubscribing from AdvertBan component state change. listener_id=[%s]', listener_id);
    delete this._state_listeners[listener_id];
  },

  processDocument: function(doc) {
    const node_name = doc.nodeName;
    if (node_name != '#document') {
      logging.info('the ducument\'s node=[%s] isn\'t html document', node_name);
      return;
    }
    const doc_location = doc.location;
    if (!doc_location) {
      logging.info('cannot determine the document\'s location for the node=[%s]', node_name);
      return;
    }
    const site_url = doc_location.href;
    logging.info('processing the document for the url=[%s]', site_url);
    const site_uri = this._createUri(site_url);
    if (!this._shouldProcessUri(site_uri)) {
      logging.info('there is no need in processing the document for the url=[%s]', site_url);
      return;
    }
    const canonical_site_url = this._getCanonicalUrl(site_uri);
    if (!this._verifyPerSiteWhitelist(canonical_site_url)) {
      this._injectCssToDocument(doc, canonical_site_url, 0);
      this._hideBlacklistedLinks(doc, canonical_site_url);
    }
  },

  executeDeferred: function(callback) {
    const main_thread = this._main_thread;
    const thread_event = {
      run: this._createErrorHandler(callback),
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
  _createErrorHandler: function(callback, default_return_value) {
    const that = this;
    const error_handler = function() {
      try {
        return callback.apply(that, arguments);
      }
      catch(e) {
        logging.error('error [%s]', e);
        logging.error('stack trace: [%s]', e.stack);
        return default_return_value;
      }
    };
    return error_handler;
  },

  _setupErrorHandlers: function(funcs) {
    logging.info('setting up error handlers for [%s]', funcs);
    funcs.forEach(function(func) {
      let default_return_value;
      if (typeof(func) != 'string') {
        default_return_value = func[1];
        func = func[0];
      }
      this[func] = this._createErrorHandler(this[func], default_return_value);
    }, this);
    logging.info('error handlers for [%s] have been set up successfully', funcs);
  },

  _getCanonicalSiteHost: function(site_url) {
    try {
      const site_uri = this._createUri(site_url);
      if (!this._shouldProcessUri(site_uri)) {
        logging.info('there is no need in processing the site_url=[%s]', site_url);
        return null;
      }
      const canonical_site_url = this._getCanonicalUrl(site_uri);
      return canonical_site_url.split('/')[0] + '/';
    }
    catch(e) {
      logging.info('cannot obtain canonical_site_host from the site_url=[%s]', site_url);
      return null;
    }
  },

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
    for (let i = 0; i < tabs_count; i++) {
      let tab = tabs[i];
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

  _notifyStateListeners: function() {
    const state_listeners = this._state_listeners;
    for (let listener_id in state_listeners) {
      logging.info('notifying AdvertBan component state listener [%s]', listener_id);
      state_listeners[listener_id]();
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
      notify: this._createErrorHandler(callback),
    };
    timer.initWithCallback(timer_callback, interval, timer.TYPE_REPEATING_SLACK);
  },

  _executeDelayed: function(timer, callback, delay) {
    const timer_callback = {
      notify: this._createErrorHandler(callback),
    };
    timer.initWithCallback(timer_callback, delay, timer.TYPE_ONE_SHOT);
  },

  _startTimers: function() {
    logging.info('starting AdvertBan component timers');
    const that = this;
    const settings = this._settings;

    // it is safe re-initializing timers in-place -
    // in this case the first callback will be automatically canceled.
    // See https://developer.mozilla.org/En/nsITimer .
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

    const save_stale_urls_callback = function() {
      that._saveStaleUrlsSync();
    };
    this._startRepeatingTimer(
        this._save_stale_urls_timer,
        save_stale_urls_callback,
        settings.save_stale_urls_interval);

    const process_stale_urls_callback = function() {
      that._processStaleUrls();
    };
    this._startRepeatingTimer(
        this._process_stale_urls_timer,
        process_stale_urls_callback,
        settings.process_stale_urls_interval);

    logging.info('AdvertBan component timers have been started');
  },

  _stopTimers: function() {
    logging.info('stopping AdvertBan component timers');
    // canceled timers can be re-used later.
    // See https://developer.mozilla.org/En/nsITimer#cancel() .
    this._update_settings_timer.cancel();
    this._save_cache_timer.cancel();
    this._save_stale_urls_timer.cancel();
    this._process_stale_urls_timer.cancel();
    logging.info('AdvertBan component timers have been stopped');
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
        // It looks like css and rss channels don't provide nsIDOMWindow
        // during redirects. Just silently skip this, because it is unclear
        // how to determine the request_origin in this case.
        // Use logging.info instead of logging.error, since this message
        // tends to spam output log for default installations too much.
        logging.info('error when obtaining request origin from channel: [%s]', e);
      }
    }
    return request_origin;
  },

  _getDataDirectory: function() {
    const data_dir = this._directory_service.get('ProfD', Ci.nsIFile);
    data_dir.append(this._DATA_DIRECTORY_NAME);
    if (!data_dir.exists() || !data_dir.isDirectory()) {
      logging.info('creating data directory for AdvertBan plugin: [%s]', data_dir.path);
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

  _getFileForPerSiteWhitelist: function() {
    const file = this._getDataDirectory();
    file.append(this._PER_SITE_WHITELIST_FILENAME);
    return file;
  },

  _getFileForStaleUrls: function() {
    const file = this._getDataDirectory();
    file.append(this._STALE_URLS_FILENAME);
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
      logging.info('the file [%s] doesn\'t exist, skipping loading from file', file.path);
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
          const data = JSON.parse(json_data);
          logging.info('stop reading from the file=[%s]', file.path);
          read_complete_callback(data);
        }
        catch(e) {
          logging.error('error when reading and parsing json from the file=[%s]: [%s]', file.path, e);
          logging.error('stack trace: [%s]', e.stack);
          throw e;
        }
      },
    };
    const stream_loader = Cc['@mozilla.org/network/stream-loader;1'].createInstance(Ci.nsIStreamLoader);
    stream_loader.init(observer);
    channel.asyncOpen(stream_loader, null);
  },

  _writeJsonToFileSync: function(file, data) {
    logging.info('start writing to the file=[%s]', file.path);
    const json_data = JSON.stringify(data);
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
    logging.info('loading AdvertBan settings from file');
    const file = this._getFileForSettings();
    const that = this;
    const read_complete_callback = function(data) {
      that._vars.auth_token = data[0];
      that._settings.import(data[1]);
      logging.info('AdvertBan settings have been loaded from file');
    };
    this._readJsonFromFileAsync(file, read_complete_callback);
  },

  _saveSettingsSync: function() {
    logging.info('saving AdvertBan settings to file');
    const file = this._getFileForSettings();
    const data = [
      this._vars.auth_token,
      this._settings.export(),
    ];
    this._writeJsonToFileSync(file, data);
    logging.info('AdvertBan settings have been saved to file');
  },

  _loadCacheAsync: function() {
    logging.info('loading AdvertBan cache from file');
    const vars = this._vars;
    const settings = this._settings;
    const stale_node_timeout = settings.stale_node_timeout;
    const node_delete_timeout = settings.node_delete_timeout;
    const file = this._getFileForCaches();
    const read_complete_callback = function(data) {
      const url_cache = Trie.importFromNodes(
          defaultUrlValue,
          stale_node_timeout,
          node_delete_timeout,
          data[0],
          urlValueConstructor);
      const url_exception_cache = Trie.importFromNodes(
          defaultUrlExceptionValue,
          stale_node_timeout,
          node_delete_timeout,
          data[1],
          urlExceptionValueConstructor);
      vars.url_cache = url_cache;
      vars.url_exception_cache = url_exception_cache;
      logging.info('AdvertBan cache has been loaded from file');
    };
    this._readJsonFromFileAsync(file, read_complete_callback);
  },

  _saveCacheSync: function() {
    logging.info('saving AdvertBan cache to file');
    const vars = this._vars;
    if (vars.is_in_private_mode) {
      logging.info('cache shouldn\'t be saved while in private mode');
      return;
    }
    const current_date = getCurrentDate();
    const url_cache = vars.url_cache;
    const url_exception_cache = vars.url_exception_cache;
    const file = this._getFileForCaches();
    const data = [
      url_cache.exportToNodes(urlNodeConstructor, current_date),
      url_exception_cache.exportToNodes(urlExceptionNodeConstructor, current_date),
    ];
    this._writeJsonToFileSync(file, data);
    logging.info('AdvertBan cache has been saved to file');
  },

  _loadPerSiteWhitelistAsync: function() {
    logging.info('loading per-site whitelist from file');
    const vars = this._vars;
    const file = this._getFileForPerSiteWhitelist();
    const read_complete_callback = function(data) {
      vars.per_site_whitelist = Trie.importFromNodes(
          defaultPerSiteWhitelistValue,
          0,
          0,
          data,
          perSiteWhitelistValueConstructor);
      logging.info('per-site whitelist has been loaded from file');
    };
    this._readJsonFromFileAsync(file, read_complete_callback);
  },

  _savePerSiteWhitelistSync: function() {
    logging.info('saving per-site whitelist to file');
    if (this._vars.is_in_private_mode) {
      logging.info('per-site whitelist shouldn\'t be saved while in private mode');
      return;
    }
    const file = this._getFileForPerSiteWhitelist();
    const data = this._vars.per_site_whitelist.exportToNodes(perSiteWhitelistNodeConstructor, 0);
    this._writeJsonToFileSync(file, data);
    logging.info('per-site whitelist has been saved to file');
  },

  _loadStaleUrlsAsync: function() {
    logging.info('loading stale urls from file');
    const vars = this._vars;
    const file = this._getFileForStaleUrls();
    const that = this;
    const read_complete_callback = function(data) {
      vars.stale_urls = that._createDictionaryFromKeys(data[0], true);
      vars.stale_url_exceptions = that._createDictionaryFromKeys(data[1], true);
      logging.info('stale urls have been loaded from file');
    };
    this._readJsonFromFileAsync(file, read_complete_callback);
  },

  _saveStaleUrlsSync: function() {
    logging.info('saving stale urls to file');
    const vars = this._vars;
    if (vars.is_in_private_mode) {
      logging.info('stale urls shouldn\'t be saved while in private mode');
      return;
    }
    const file = this._getFileForStaleUrls();
    const data = [
      this._getAllDictionaryKeys(vars.stale_urls),
      this._getAllDictionaryKeys(vars.stale_url_exceptions),
    ];
    this._writeJsonToFileSync(file, data);
    logging.info('stale urls have been saved to file');
  },

  _processStaleUrls: function() {
    logging.info('processing stale urls');
    const vars = this._vars;
    const unverified_urls = vars.unverified_urls;
    const unverified_url_exceptions = vars.unverified_url_exceptions;
    let stale_urls_count = 0;
    let stale_url_exceptions_count = 0;
    for (let url in vars.stale_urls) {
      unverified_urls[url] = true;
      stale_urls_count++;
    }
    for (let url in vars.stale_url_exceptions) {
      unverified_url_exceptions[url] = true;
      stale_url_exceptions_count++;
    }
    vars.stale_urls = {};
    vars.stale_url_exceptions = {};
    if (stale_urls_count || stale_url_exceptions_count) {
      this._saveStaleUrlsSync();
      this._launchUrlVerifier();
    }
    logging.info('stale urls have been processed: [%s] urls and [%s] url exceptions', stale_urls_count, stale_url_exceptions_count);
  },

  _shouldProcessUri: function(uri) {
    return (uri.scheme in this._FILTERED_SCHEMES);
  },

  _injectCssToDocument: function(doc, canonical_site_url, generation_count) {
    const [url_exception_value, is_todo] = this._getUrlExceptionValue(canonical_site_url);
    if (is_todo) {
      logging.info('css_selectors aren\'t available yet for the canonical_site_url=[%s]', canonical_site_url);
      if (generation_count < this._settings.max_todo_generation_count) {
        this._vars.todo_docs.push([canonical_site_url, doc, generation_count]);
      }
      else {
        logging.warning('couldn\'t obtain css_selectors for the canonical_site_url=[%s] in [%s] tries', canonical_site_url, generation_count);
      }
      return;
    }

    const css_selectors = url_exception_value.css_selectors;
    if (css_selectors) {
      const style = doc.createElement('style');
      style.type = 'text/css';
      const style_text = css_selectors + '{display: none !important;}';
      const style_text_node = doc.createTextNode(style_text);
      style.appendChild(style_text_node);
      logging.info('adding css selector=[%s] to the canonical_site_url=[%s]', style_text, canonical_site_url);
      doc.getElementsByTagName('head')[0].appendChild(style);
    }
  },

  _closePopup: function(node, canonical_url) {
    const w = node.contentWindow;
    const opener_url = w.opener.location.href;
    logging.info('closing the popup for canonical_url=[%s], opener_url=[%s]', canonical_url, opener_url);
    w.close();
  },

  _hideNode: function(node) {
    node.style.display = 'none';
  },

  _hideBlacklistedLinks: function(doc, canonical_site_url) {
    const [url_exception_value, is_todo1] = this._getUrlExceptionValue(canonical_site_url);
    const todo_nodes = this._vars.todo_nodes;
    Array.prototype.forEach.call(doc.links, function(link) {
      let uri = this._createUri(link.href);
      if (!this._shouldProcessUri(uri)) {
        logging.info('there is no need in processing the link=[%s]', uri.spec);
        return;
      }
      let canonical_url = this._getCanonicalUrl(uri);
      let is_whitelist = this._verifyUrlException(canonical_url, url_exception_value, canonical_site_url);
      let is_todo2 = false;
      if (is_whitelist == null) {
        [is_whitelist, is_todo2] = this._verifyUrl(canonical_url);
      }
      if (!is_whitelist) {
        logging.info('hiding the link=[%s]', canonical_url);
        this._hideNode(link);
      }
      else if (is_todo1 || is_todo2) {
        todo_nodes.push([canonical_url, canonical_site_url, link, 0]);
      }
    }, this);
  },

  _updateCache: function(response_data, response_values, urls, cache, value_constructor) {
    const current_date = getCurrentDate();
    response_data.forEach(function(data) {
      let [url_length, todo, url_idx, value_index] = data;
      url_idx = uncompressIndexes(url_idx);
      let end_urls = url_idx.map(function(idx) {
        return urls[idx];
      });
      let url = end_urls[0].substring(0, url_length);
      let values = response_values[value_index];
      let value = value_constructor(values);
      cache.update(url, end_urls, value, current_date, todo);
    });
  },

  _getDictionaryKeys: function(dict, max_keys_to_return) {
    const keys = [];
    for (let key in dict) {
      if (max_keys_to_return <= 0) {
        logging.info('hit the maximum number of keys to return: [%s]', keys.length);
        break;
      }
      --max_keys_to_return;
      keys.push(key);
    }
    return keys;
  },

  _getAllDictionaryKeys: function(dict) {
    return this._getDictionaryKeys(dict, Infinity);
  },

  _createDictionaryFromKeys: function(keys, value) {
    const dict = {};
    keys.forEach(function(key) {
      dict[key] = value;
    });
    return dict;
  },

  _cleanupUnverifiedUrls: function(unverified_urls, cache) {
    const current_date = getCurrentDate();
    const urls = this._getAllDictionaryKeys(unverified_urls);
    urls.forEach(function(url) {
      let tmp = cache.get(url);
      let non_empty_node = tmp[2];
      if (!cache.isStaleNode(non_empty_node, current_date)) {
        delete unverified_urls[url];
      }
    });
  },

  _cleanupTodoNodes: function() {
    const vars = this._vars;
    const todo_nodes = vars.todo_nodes;
    const max_todo_generation_count = this._settings.max_todo_generation_count;
    vars.todo_nodes = [];
    todo_nodes.forEach(function(todo_node) {
      let [canonical_url, canonical_site_url, node, generation_count] = todo_node;
      let is_whitelist = null;
      let is_todo1 = false;
      let is_todo2 = false;
      if (canonical_site_url) {
        let url_exception_value;
        [url_exception_value, is_todo1] = this._getUrlExceptionValue(canonical_site_url);
        is_whitelist = this._verifyUrlException(canonical_url, url_exception_value, canonical_site_url);
      }
      if (is_whitelist == null) {
        [is_whitelist, is_todo2] = this._verifyUrl(canonical_url);
      }
      if (!is_whitelist) {
        try {
          logging.info('hiding todo node=[%s] for canonical_url=[%s], canonical_site_url=[%s]', node.nodeName, canonical_url, canonical_site_url);
          this._hideNode(node);
        }
        catch(e) {
          logging.error('error when hiding the node=[%s] for canonical_url=[%s], canonical_site_url=[%s]: [%s]', node.nodeName, canonical_url, canonical_site_url, e);
          logging.error('stack trace: [%s]', e.stack);
        }
      }
      else if (is_todo1 || is_todo2) {
        logging.info('the todo node=[%s] for canonical_url=[%s], canonical_site_url=[%s] cannot be processed now', node.nodeName, canonical_url, canonical_site_url);
        generation_count++;
        if (generation_count < max_todo_generation_count) {
          vars.todo_nodes.push([canonical_url, canonical_site_url, node, generation_count]);
        }
        else {
          logging.warning('couldn\'t process the todo node=[%s] for canonical_url=[%s], canonical_site_url=[%s] in [%s] tries', node.nodeName, canonical_url, canonical_site_url, generation_count);
        }
      }
    }, this);
  },

  _cleanupTodoDocs: function() {
    const vars = this._vars;
    const todo_docs = vars.todo_docs;
    vars.todo_docs = [];
    todo_docs.forEach(function(todo_doc) {
      let [canonical_site_url, doc, generation_count] = todo_doc;
      try {
        this._injectCssToDocument(doc, canonical_site_url, generation_count + 1);
      }
      catch(e) {
        logging.error('error when hiding the todo doc for canonical_site_url=[%s]: [%s]', canonical_site_url, e);
        logging.error('stack trace: [%s]', e.stack);
      }
    }, this);
  },

  _cleanupTodoPopups: function() {
    const vars = this._vars;
    const todo_popups = vars.todo_popups;
    const max_todo_generation_count = this._settings.max_todo_generation_count;
    vars.todo_popups = [];
    todo_popups.forEach(function(todo_popup) {
      let [canonical_url, node, generation_count] = todo_popup;
      let [is_whitelist, is_todo] = this._verifyUrl(canonical_url);
      if (!is_whitelist) {
        try {
          this._closePopup(node, canonical_url);
        }
        catch(e) {
          logging.error('cannot close the todo popup for canonical_url=[%s]: [%s]', canonical_url, e);
          logging.error('stack trace: [%s]', e.stack);
        }
      }
      else if (is_todo) {
        logging.info('the todo popup for canonical_url=[%s] cannot be processed now', canonical_url);
        generation_count++;
        if (generation_count < max_todo_generation_count) {
          vars.todo_popups.push([canonical_url, node, generation_count]);
        }
        else {
          logging.warning('couldn\'t process the todo popup for canonical_url=[%s] in [%s] tries', canonical_url, generation_count);
        }
      }
    }, this);
  },

  _injectAuthTokenToCookie: function(auth_token) {
    const host = this._AUTH_COOKIE_HOST;
    logging.info('injecting auth_token=[%s] into cookie for the host=[%s]', auth_token, host);
    const expiration_time = 0x7fffffff;
    // see https://developer.mozilla.org/en/XPCOM_Interface_Reference/nsICookieManager2#add() .
    this._cookie_manager.add(host, '/', 'a', auth_token, false, false, false, expiration_time);
  },

  _processJsonResponse: function(request_text, response_text, response_callback) {
    const error_codes = this._ERROR_CODES;
    const vars = this._vars;
    let error_message;

    logging.info('response_text=[%s]', response_text);
    const response_data = JSON.parse(response_text);
    const error_code = response_data[0];
    if (error_code == error_codes.NO_ERRORS) {
      const new_auth_token = response_data[2];
      if (new_auth_token) {
        logging.info('obtained new auth_token=[%s] from the response_text=[%s]. request_text=[%s]', new_auth_token, response_text, request_text);
        vars.auth_token = new_auth_token;
        // immediately save new auth_token into the file.
        this._saveSettingsSync();
      }
      // refresh the auth token in cookie after each request to the server
      // in order to properly open pages protected by authentication such
      // as user status page (this.USER_STATUS_URL).
      this._injectAuthTokenToCookie(vars.auth_token);
      if (response_callback) {
        response_callback(response_data[1]);
      }
    }
    else if (error_code == error_codes.AUTHENTICATION_ERROR) {
      logging.error('authentication failed for the auth_token=[%s]. Resetting the auth_token.', vars.auth_token);
      vars.auth_token = '';
      this._saveSettingsSync();
      error_message = 'authentication error';
    }
    else if (error_code == error_codes.AUTHORIZATION_ERROR) {
      logging.warning('authorization failed for the auth_token=[%s]. Opening a user status tab', vars.auth_token);
      this.openTab('user-status', this.USER_STATUS_URL);
      error_message = 'authorization error';
    }
    else {
      logging.error('server responded with the error_code=[%s] for the request_text=[%s]. response_text=[%s]', error_code, request_text, response_text);
      error_message = 'unexpected server error';
    }
    return error_message;
  },

  _startJsonRequestInternal: function(xhr, request_url, request_data, response_callback, finish_callback) {
    let error_message;
    const request_text = JSON.stringify([this._vars.auth_token, request_data]);
    logging.info('request_url=[%s], request_text=[%s]', request_url, request_text);

    const that = this;
    xhr.onreadystatechange = function() {
      if (xhr.readyState != 4) {
        return;
      }
      try {
        const http_status = xhr.status;
        if (http_status == 200) {
          error_message = that._processJsonResponse(request_text, xhr.responseText, response_callback);
        }
        else {
          logging.error('unexpected HTTP status code for the request_url=[%s], request_text=[%s], http_status=[%s]', request_url, request_text, http_status);
          error_message = 'server error';
        }
      }
      catch(e) {
        logging.error('error when processing json response=[%s] for the request_url=[%s], request_text=[%s]: [%s]', xhr.responseText, request_url, request_text, e);
        logging.error('stack trace: [%s]', e.stack);
        error_message = 'protocol error';
      }
      finally {
        finish_callback = that._createErrorHandler(finish_callback);
        finish_callback(error_message);
      }
    };
    xhr.open('POST', request_url, true);
    xhr.send(request_text);
  },

  _startJsonRequest: function(xhr, request_url, request_data, response_callback, finish_callback) {
    const current_date = getCurrentDate();
    const last_failed_request_date = xhr._last_failed_request_date;
    if (last_failed_request_date && current_date - last_failed_request_date < xhr._backoff_timeout) {
      const time_to_wait = xhr._backoff_timeout - (current_date - last_failed_request_date);
      logging.warning('backoff timeout=[%s] since the previous unsuccessful request to the url=[%s] isn\'t over yet. Time to wait=[%s]', xhr._backoff_timeout, request_url, time_to_wait);
      if (finish_callback) {
        finish_callback('remote service is temporarily unavailable');
      }
      return;
    }

    const that = this;
    const finish_callback_wrapper = function(error_message) {
      if (error_message) {
        xhr._last_failed_request_date = getCurrentDate();
        const settings = that._settings;
        let backoff_timeout = xhr._backoff_timeout;
        if (!backoff_timeout) {
          backoff_timeout = settings.min_backoff_timeout;
        }
        else if (backoff_timeout < settings.max_backoff_timeout) {
          backoff_timeout *= 2;
        }
        xhr._backoff_timeout = backoff_timeout;
        logging.warning('Request to the url=[%s] failed. Setting the backoff timeout for subsequent requests to [%s] milliseconds', request_url, backoff_timeout);
      }
      else if ('_last_failed_request_date' in xhr) {
        delete xhr._last_failed_request_date;
        delete xhr._backoff_timeout;
      }
      if (finish_callback) {
        finish_callback(error_message);
      }
    };
    this._startJsonRequestInternal(xhr, request_url, request_data, response_callback, finish_callback_wrapper);
  },

  _readSettingsFromServer: function() {
    const request_data = [];
    const settings = this._settings;
    const vars = this._vars;
    const url_cache = vars.url_cache;
    const url_exception_cache = vars.url_exception_cache;
    const that = this;
    const response_callback = function(response) {
      settings.import(response);
      // save settings on the local storage syncrhonously to be sure they
      // are stored in a consistent state.
      that._saveSettingsSync();
      that._stopTimers();
      that._startTimers();
      url_cache.setStaleNodeTimeout(settings.stale_node_timeout);
      url_cache.setNodeDeleteTimeout(settings.node_delete_timeout);
      url_exception_cache.setStaleNodeTimeout(settings.stale_node_timeout);
      url_exception_cache.setNodeDeleteTimeout(settings.node_delete_timeout);
    };
    this._startJsonRequest(this._update_settings_xhr, this._READ_SETTINGS_ENDPOINT, request_data, response_callback);
  },

  _verifyUrls: function(verification_complete_callback) {
    const vars = this._vars;
    const settings = this._settings;
    const urls = this._getDictionaryKeys(vars.unverified_urls, settings.max_urls_per_request);
    const url_exceptions = this._getDictionaryKeys(vars.unverified_url_exceptions, settings.max_urls_per_request);

    // sort urls and url_exceptions in order to achieve better compression.
    urls.sort();
    url_exceptions.sort();

    const request_data = [
      compressStrings(urls),
      compressStrings(url_exceptions),
    ];

    const that = this;
    const response_callback = function(response) {
      that._updateCache(
          response[0],
          response[2],
          urls,
          vars.url_cache,
          urlValueConstructor);
      that._updateCache(
          response[1],
          response[3],
          url_exceptions,
          vars.url_exception_cache,
          urlExceptionValueConstructor);
      that._cleanupUnverifiedUrls(vars.unverified_urls, vars.url_cache);
      that._cleanupUnverifiedUrls(vars.unverified_url_exceptions, vars.url_exception_cache);
    };
    this._startJsonRequest(this._verify_urls_xhr, this._VERIFY_URLS_ENDPOINT, request_data, response_callback, verification_complete_callback);
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
    const verification_complete_callback = function(error_message) {
      logging.info('url verifier stopped');
      if (error_message) {
        logging.warning('error while verifying urls: [%s]', error_message);
        logging.info('flushing unverified_urls and unverified_url_exceptions in order to prevent memory leaks');
        vars.unverified_urls = {};
        vars.unverified_url_exceptions = {};
      }

      // Clean up todo items here, since this callback is always called
      // in the response to the call to the _verifyUrls().
      // So it is guaranteed that todo items won't leak in the face
      // of arbitrary errors.
      that._cleanupTodoNodes();
      that._cleanupTodoDocs();
      that._cleanupTodoPopups();

      vars.is_url_verifier_active = false;
      that._launchUrlVerifier();
    };
    const verify_urls_callback = function() {
      that._verifyUrls(verification_complete_callback);
    };
    this._executeDelayed(this._verify_urls_timer, verify_urls_callback, this._settings.url_verifier_delay);
  },

  _getCacheValue: function(cache, stale_urls, unverified_urls, url, max_url_length) {
    const tmp = cache.get(url);
    const node_with_value = tmp[1];
    const non_empty_node = tmp[2];
    const node_depth = tmp[3];
    const is_todo = cache.isTodoNode(non_empty_node);
    if (cache.isStaleNode(non_empty_node, getCurrentDate())) {
      if (is_todo) {
        url = url.substring(0, max_url_length);
        unverified_urls[url] = true;
        this._launchUrlVerifier();
      }
      else {
        // An optimization: delay verification of stale urls in order to be able verifying
        // them in a single batch request - see processStaleUrls() for details.
        // The processStaleUrls() is repeatedly called with the interval defined
        // in settings.process_stale_urls_interval.
        // This optimization can significantly reduce the number of url verification calls
        // to the server after the initial cache of ad filters specific for the current user
        // has been loaded.
        url = url.substring(0, node_depth);
        stale_urls[url] = true;
      }
    }
    return [cache.getValue(node_with_value), is_todo];
  },

  _getUrlValue: function(url) {
    const vars = this._vars;
    return this._getCacheValue(vars.url_cache, vars.stale_urls, vars.unverified_urls, url, this._settings.max_url_length);
  },

  _getUrlExceptionValue: function(url) {
    const vars = this._vars;
    return this._getCacheValue(vars.url_exception_cache, vars.stale_url_exceptions, vars.unverified_url_exceptions, url, this._settings.max_url_exception_length);
  },

  _isIp: function(host_parts) {
    if (host_parts[0].indexOf(':') != -1) {
      // IPv6 address
      return true;
    }
    if (host_parts.length == 4) {
      for (let i = 0; i < 4; i++) {
        let part = host_parts[i];
        let int_part = parseInt(part);
        if (int_part != part || int_part < 0 || int_part > 255) {
          return false;
        }
      }
      // IPv4 address
      return true;
    }
    return false;
  },

  _getCanonicalUrl: function(uri) {
    uri = uri.clone();

    // reverse domain parts if this is not an IP
    const host_parts = uri.host.split('.');
    if (!this._isIp(host_parts)) {
      uri.host = host_parts.reverse().join('.');
    }
    uri.userPass = '';

    // Use dummy scheme, which will be removed later.
    uri.scheme = 'http';
    // remove dummy scheme and lowercase the url
    return uri.spec.substring(7).toLowerCase();
  },

  _matchesRegexp: function(reg_exp, s) {
    if (!reg_exp) {
      return false;
    }
    return (s.search(reg_exp) != -1);
  },

  _verifyUrl: function(canonical_url) {
    const [url_value, is_todo] = this._getUrlValue(canonical_url);
    if (this._matchesRegexp(url_value.whitelist_regexp, canonical_url)) {
      logging.info('the canonical_url=[%s] is whitelisted via own regexp', canonical_url);
      return [true, is_todo];
    }
    if (this._matchesRegexp(url_value.blacklist_regexp, canonical_url)) {
      logging.info('the canonical_url=[%s] is blacklisted via own regexp', canonical_url);
      return [false, is_todo];
    }
    return [url_value.is_whitelist, is_todo];
  },

  _verifyUrlException: function(canonical_url, url_exception_value, canonical_site_url) {
    if (this._matchesRegexp(url_exception_value.whitelist_regexp, canonical_url)) {
      logging.info('the canonical_url=[%s] is whitelisted via url exception regexp for canonical_site_url=[%s]', canonical_url, canonical_site_url);
      return true;
    }
    if (this._matchesRegexp(url_exception_value.blacklist_regexp, canonical_url)) {
      logging.info('the canonical_url=[%s] is blacklisted via url exception regexp for canonical_site_url=[%s]', canonical_url, canonical_site_url);
      return false;
    }
    return null;
  },

  _verifyPerSiteWhitelist: function(canonical_site_url) {
    const per_site_whitelist = this._vars.per_site_whitelist;
    const node_with_value = per_site_whitelist.get(canonical_site_url)[1];
    return per_site_whitelist.getValue(node_with_value);
  },

  _verifyLocation: function(content_location, request_origin) {
    if (!this._shouldProcessUri(content_location)) {
      return [true, false, null, null];
    }
    const canonical_url = this._getCanonicalUrl(content_location);

    let is_whitelist = null;
    let is_todo1 = false;
    let is_todo2 = false;
    let canonical_site_url = null;
    if (request_origin && this._shouldProcessUri(request_origin)) {
      canonical_site_url = this._getCanonicalUrl(request_origin);
      if (this._verifyPerSiteWhitelist(canonical_site_url)) {
        is_whitelist = true;
      }
      else {
        let url_exception_value;
        [url_exception_value, is_todo1] = this._getUrlExceptionValue(canonical_site_url);
        is_whitelist = this._verifyUrlException(canonical_url, url_exception_value, canonical_site_url);
      }
    }
    if (is_whitelist == null) {
      if (!canonical_site_url && this._verifyPerSiteWhitelist(canonical_url)) {
        is_whitelist = true;
        is_todo1 = false;
      }
      else {
        [is_whitelist, is_todo2] = this._verifyUrl(canonical_url);
      }
    }

    const is_todo = is_todo1 || is_todo2;
    logging.info('is_whitelist=[%s], is_todo=[%s], original=[%s], canonical_url=[%s], canonical_site_url=[%s]', is_whitelist, is_todo, content_location.spec, canonical_url, canonical_site_url);
    return [is_whitelist, is_todo, canonical_url, canonical_site_url];
  },
};

// XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
// XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
if (XPCOMUtils.generateNSGetFactory) {
  const NSGetFactory = XPCOMUtils.generateNSGetFactory([AdvertBan]);
}
else {
  const NSGetModule = XPCOMUtils.generateNSGetModule([AdvertBan]);
}

