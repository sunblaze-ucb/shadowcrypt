// this is from from http://crypto.stanford.edu/sjcl/sjcl.js
// narrowed down to bitArray and hex
var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};sjcl.bitArray={bitSlice:function(a,b,c){a=sjcl.bitArray.P(a.slice(b/32),32-(b&31)).slice(1);return c===undefined?a:sjcl.bitArray.clamp(a,c-b)},extract:function(a,b,c){var d=Math.floor(-b-c&31);return((b+c-1^b)&-32?a[b/32|0]<<32-d^a[b/32+1|0]>>>d:a[b/32|0]>>>d)&(1<<c)-1},concat:function(a,b){if(a.length===0||b.length===0)return a.concat(b);var c=a[a.length-1],d=sjcl.bitArray.getPartial(c);return d===32?a.concat(b):sjcl.bitArray.P(b,d,c|0,a.slice(0,a.length-1))},bitLength:function(a){var b=a.length;if(b===0)return 0;return(b-1)*32+sjcl.bitArray.getPartial(a[b-1])},clamp:function(a,b){if(a.length*32<b)return a;a=a.slice(0,Math.ceil(b/32));var c=a.length;b&=31;if(c>0&&b)a[c-1]=sjcl.bitArray.partial(b,a[c-1]&2147483648>>b-1,1);return a},partial:function(a,b,c){if(a===32)return b;return(c?b|0:b<<32-a)+a*0x10000000000},getPartial:function(a){return Math.round(a/0x10000000000)||32},equal:function(a,b){if(sjcl.bitArray.bitLength(a)!==sjcl.bitArray.bitLength(b))return false;var c=0,d;for(d=0;d<a.length;d++)c|=a[d]^b[d];return c===0},P:function(a,b,c,d){var e;e=0;if(d===undefined)d=[];for(;b>=32;b-=32){d.push(c);c=0}if(b===0)return d.concat(a);for(e=0;e<a.length;e++){d.push(c|a[e]>>>b);c=a[e]<<32-b}e=a.length?a[a.length-1]:0;a=sjcl.bitArray.getPartial(e);d.push(sjcl.bitArray.partial(b+a&31,b+a>32?c:d.pop(),1));return d},k:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};sjcl.codec.hex={fromBits:function(a){var b="",c;for(c=0;c<a.length;c++)b+=((a[c]|0)+0xf00000000000).toString(16).substr(4);return b.substr(0,sjcl.bitArray.bitLength(a)/4)},toBits:function(a){var b,c=[],d;a=a.replace(/\s|0x/g,"");d=a.length;a+="00000000";for(b=0;b<a.length;b+=8)c.push(parseInt(a.substr(b,8),16)^0);return sjcl.bitArray.clamp(c,d*4)}};

var MAX_ERROR = 1;

var Model = {
	SITE_KEY_PATTERN: /^origin-(.*)$/,
	SUFFIX_PATTERN: /^\w*$/,

	STORAGE_ERROR: MAX_ERROR++,
	ORIGIN_NORMALIZE_ERROR: MAX_ERROR++,
	SUFFIX_FORMAT_ERROR: MAX_ERROR++,
	KEY_LENGTH_ERROR: MAX_ERROR++,
	COLLISION_ERROR: MAX_ERROR++,
	REMOVE_DEFAULT_ERROR: MAX_ERROR++,
	KEY_REFERENCE_ERROR: MAX_ERROR++,
	SITE_REFERENCE_ERROR: MAX_ERROR++,

	db: {}
};

Model.checkStorageError = function (onError) {
	if (chrome.runtime.lastError) {
		onError(Model.STORAGE_ERROR);
		return true;
	}
	return false;
};

Model.init = function (onAddSite, onAddKey, onError) {
	chrome.storage.sync.get(function (items) {
		if (Model.checkStorageError(onError)) return;
		for (var key in items) {
			var m = Model.SITE_KEY_PATTERN.exec(key);
			if (!m) continue;
			var origin = m[1];
			var site = items[key];
			Model.db[origin] = site;
			onAddSite(origin, site);
			for (var suffix in site.keys) {
				onAddKey(origin, suffix, suffix === site.defaultSuffix, site.keys[suffix]);
			}
		}
	});
};

Model.validateOrigin = function (origin, onError) {
	var url;
	try {
		var url = new URL(origin + '/');
	} catch (e) {
		onError(Model.ORIGIN_NORMALIZE_ERROR);
		return true;
	}
	if (url.origin !== origin) {
		onError(Model.ORIGIN_NORMALIZE_ERROR);
		return true;
	}
	return false;
};

Model.validateSuffix = function (suffix, onError) {
	if (!Model.SUFFIX_PATTERN.test(suffix)) {
		onError(Model.SUFFIX_FORMAT_ERROR);
		return true;
	}
	return false;
};

Model.validateKey = function (key, onError) {
	switch (sjcl.bitArray.bitLength(key)) {
	case 128:
	case 192:
	case 256:
		return false;
	default:
		onError(Model.KEY_LENGTH_ERROR);
		return true;
	}
};

Model.add = function (origin, suffix, key, onAddSite, onAddKey, onSuccess, onError) {
	if (Model.validateOrigin(origin, onError)) return;
	if (Model.validateSuffix(suffix, onError)) return;
	if (Model.validateKey(key, onError)) return;
	if (origin in Model.db) {
		var site = Model.db[origin];
		if (suffix in site.keys) {
			onError(Model.COLLISION_ERROR);
		} else {
			site.keys[suffix] = key;
			var items = {};
			items['origin-' + origin] = site;
			chrome.storage.sync.set(items, function () {
				if (Model.checkStorageError(onError)) {
					delete site.keys[suffix];
				} else {
					onAddKey(origin, suffix, false, key);
					onSuccess();
				}
			});
		}
	} else {
		var site = {keys: {}, defaultSuffix: null};
		site.keys[suffix] = key;
		site.defaultSuffix = suffix;
		Model.db[origin] = site;
		var items = {};
		items['origin-' + origin] = site;
		chrome.storage.sync.set(items, function () {
			if (Model.checkStorageError(onError)) {
				delete Model.db[origin];
			} else {
				onAddSite(origin, site);
				onAddKey(origin, suffix, true, key);
				onSuccess();
			}
		});
	}
};

Model.removeSite = function (origin, onRemoveSite, onSuccess, onError) {
	if (origin in Model.db) {
		var site = Model.db[origin];
		delete Model.db[origin];
		chrome.storage.sync.remove(['origin-' + origin], function () {
			if (Model.checkStorageError(onError)) {
				Model.db[origin] = site;
			} else {
				onRemoveSite(origin);
				onSuccess();
			}
		});
	} else {
		onError(Model.SITE_REFERENCE_ERROR);
	}
};

Model.removeKey = function (origin, suffix, onRemoveKey, onSuccess, onError) {
	if (origin in Model.db) {
		var site = Model.db[origin];
		if (suffix === site.defaultSuffix) {
			onError(Model.REMOVE_DEFAULT_ERROR);
		} else if (suffix in site.keys) {
			var key = site.keys[suffix];
			delete site.keys[suffix];
			var items = {};
			items['origin-' + origin] = site;
			chrome.storage.sync.set(items, function () {
				if (Model.checkStorageError(onError)) {
					site.keys[suffix] = key;
				} else {
					onRemoveKey(origin, suffix);
					onSuccess();
				}
			});
		} else {
			onError(Model.KEY_REFERENCE_ERROR);
		}
	} else {
		onError(Model.KEY_REFERENCE_ERROR);
	}
};

Model.setDefault = function (origin, suffix, onSetDefault, onSuccess, onError) {
	if (origin in Model.db) {
		var site = Model.db[origin];
		if (suffix in site.keys) {
			var oldSuffix = site.defaultSuffix;
			site.defaultSuffix = suffix;
			var items = {};
			items['origin-' + origin] = site;
			chrome.storage.sync.set(items, function () {
				if (Model.checkStorageError(onError)) {
					site.defaultSuffix = oldSuffix;
				} else {
					onSetDefault(origin, suffix);
					onSuccess();
				}
			});
		} else {
			onError(Model.KEY_REFERENCE_ERROR);
		}
	} else {
		onError(Model.KEY_REFERENCE_ERROR);
	}
};

var View = {
	errorMessages: {},
	messageDisplay: null,
	importForm: null,
	importField: null,
	generateForm: null,
	originField: null,
	suffixField: null,
	list: null
};

View.init = function () {
	// in init() because not all error codes are declared until the bottom
	View.errorMessages[Model.STORAGE_ERROR] = 'Error saving change';
	View.errorMessages[Model.ORIGIN_NORMALIZE_ERROR] = 'Website must be specified as an origin';
	View.errorMessages[Model.SUFFIX_FORMAT_ERROR] = 'Key name must contain only letters, numbers, and underscores';
	View.errorMessages[Model.KEY_LENGTH_ERROR] = 'Key must be 128, 192, or 256 bits';
	View.errorMessages[Model.COLLISION_ERROR] = 'You already have a key with that name on that site';
	View.errorMessages[Model.REMOVE_DEFAULT_ERROR] = 'Cannot delete a site\'s default key';
	View.errorMessages[Model.KEY_REFERENCE_ERROR] = 'The specified key does not exist';
	View.errorMessages[Model.SITE_REFERENCE_ERROR] = 'The specified site does not exist';
	View.errorMessages[Controller.IMPORT_FORMAT_ERROR] = 'Malformed key specification';

	View.messageDisplay = document.getElementById('messageDisplay');
	View.importForm = document.getElementById('importForm');
	View.importField = document.getElementById('importField');
	View.generateForm = document.getElementById('generateForm');
	View.originField = document.getElementById('originField');
	View.suffixField = document.getElementById('suffixField');
	View.list = document.getElementById('list');

	View.importForm.addEventListener('submit', function (e) {
		e.preventDefault();
		Controller.importKey(importField.value);
	});

	View.generateForm.addEventListener('submit', function (e) {
		e.preventDefault();
		Controller.generateKey(originField.value, suffixField.value);
	});
};

View.showMessage = function (className, message) {
	View.messageDisplay.className = className;
	View.messageDisplay.textContent = message;
	View.messageDisplay.style.visibility = '';
};

View.hideMessage = function () {
	View.messageDisplay.style.visibility = 'hidden';
};

View.onSuccess = function () {
	View.hideMessage();
};

View.onError = function (error) {
	var message = View.errorMessages[error] || '' + error;
	View.showMessage('error', message);
};

View.onAddSite = function (origin, site) {
	var div = document.createElement('div');
	div.id = 'site-' + origin;
	div.className = 'site';
	var button = document.createElement('input');
	button.type = 'button';
	button.className = 'delete deleteSite';
	button.value = 'Delete';
	button.addEventListener('click', function (e) {
		Controller.removeSite(origin);
	});
	div.appendChild(button);
	var h1 = document.createElement('h1');
	h1.className = 'origin';
	var a = document.createElement('a');
	a.href = origin + '/';
	a.target = '_blank';
	a.textContent = origin;
	h1.appendChild(a);
	div.appendChild(h1);
	var ul = document.createElement('ul');
	ul.className = 'keys';
	div.appendChild(ul);
	View.list.appendChild(div);
};

View.onRemoveSite = function (origin) {
	var div = document.getElementById('site-' + origin);
	div.parentNode.removeChild(div);
};

View.onAddKey = function (origin, suffix, isDefault, key) {
	var div = document.getElementById('site-' + origin);
	var ul = div.querySelector('.keys');
	var li = document.createElement('li');
	li.id = 'key-' + origin + '/' + suffix;
	li.className = 'key';
	var radio = document.createElement('input');
	radio.type = 'radio';
	radio.className = 'default';
	radio.name = origin;
	radio.value = suffix;
	radio.checked = isDefault;
	radio.addEventListener('click', function (e) {
		e.preventDefault();
		Controller.setDefault(origin, suffix);
	});
	li.appendChild(radio);
	var span = document.createElement('span');
	span.className = 'suffix';
	span.textContent = suffix;
	li.appendChild(span);
	var button = document.createElement('input');
	button.type = 'button';
	button.className = 'delete deleteKey';
	button.value = 'Delete';
	button.addEventListener('click', function (e) {
		Controller.removeKey(origin, suffix);
	});
	li.appendChild(button);
	var p = document.createElement('p');
	p.className = 'share';
	p.textContent = origin + ' [' + suffix + '] ' + sjcl.codec.hex.fromBits(key);
	li.appendChild(p);
	ul.appendChild(li);
};

View.onRemoveKey = function (origin, suffix) {
	var li = document.getElementById('key-' + origin + '/' + suffix);
	li.parentNode.removeChild(li);
};

View.onSetDefault = function (origin, suffix) {
	var li = document.getElementById('key-' + origin + '/' + suffix);
	var radio = li.querySelector('.default');
	radio.checked = true;
};

var Controller = {
	IMPORT_PATTERN: /^(\S*) \[(\w*)\] ([0-9A-Fa-f]+)$/,
	KEY_LENGTH: 4,

	IMPORT_FORMAT_ERROR: MAX_ERROR++
};

Controller.importKey = function (spec) {
	var m = Controller.IMPORT_PATTERN.exec(spec);
	if (m) {
		var origin = m[1];
		var suffix = m[2];
		var key = sjcl.codec.hex.toBits(m[3]);
		Model.add(origin, suffix, key, View.onAddSite, View.onAddKey, View.onSuccess, View.onError);
	} else {
		View.onError(Controller.IMPORT_FORMAT_ERROR);
	}
};

Controller.generateKey = function (origin, suffix) {
	var key = Array.prototype.slice.call(window.crypto.getRandomValues(new Uint32Array(Controller.KEY_LENGTH)));
	Model.add(origin, suffix, key, View.onAddSite, View.onAddKey, View.onSuccess, View.onError);
};

Controller.removeSite = function (origin) {
	Model.removeSite(origin, View.onRemoveSite, View.onSuccess, View.onError);
};

Controller.removeKey = function (origin, suffix) {
	Model.removeKey(origin, suffix, View.onRemoveKey, View.onSuccess, View.onError);
};

Controller.setDefault = function (origin, suffix) {
	Model.setDefault(origin, suffix, View.onSetDefault, View.onSuccess, View.onError);
};

Controller.init = function () {
	View.init();
	Model.init(View.onAddSite, View.onAddKey, View.onError);
};

Controller.init();
