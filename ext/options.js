// this is sjcl configured with:
// --compress=yui --without-all --with-bitArray --with-codecHex
var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};sjcl.bitArray={bitSlice:function(b,c,d){b=sjcl.bitArray._shiftRight(b.slice(c/32),32-(c&31)).slice(1);return(d===undefined)?b:sjcl.bitArray.clamp(b,d-c)},extract:function(c,d,f){var b,e=Math.floor((-d-f)&31);if((d+f-1^d)&-32){b=(c[d/32|0]<<(32-e))^(c[d/32+1|0]>>>e)}else{b=c[d/32|0]>>>e}return b&((1<<f)-1)},concat:function(c,a){if(c.length===0||a.length===0){return c.concat(a)}var d,e,f=c[c.length-1],b=sjcl.bitArray.getPartial(f);if(b===32){return c.concat(a)}else{return sjcl.bitArray._shiftRight(a,b,f|0,c.slice(0,c.length-1))}},bitLength:function(d){var c=d.length,b;if(c===0){return 0}b=d[c-1];return(c-1)*32+sjcl.bitArray.getPartial(b)},clamp:function(d,b){if(d.length*32<b){return d}d=d.slice(0,Math.ceil(b/32));var c=d.length;b=b&31;if(c>0&&b){d[c-1]=sjcl.bitArray.partial(b,d[c-1]&2147483648>>(b-1),1)}return d},partial:function(b,a,c){if(b===32){return a}return(c?a|0:a<<(32-b))+b*0x10000000000},getPartial:function(a){return Math.round(a/0x10000000000)||32},equal:function(e,d){if(sjcl.bitArray.bitLength(e)!==sjcl.bitArray.bitLength(d)){return false}var c=0,f;for(f=0;f<e.length;f++){c|=e[f]^d[f]}return(c===0)},_shiftRight:function(d,c,h,f){var g,b=0,e;if(f===undefined){f=[]}for(;c>=32;c-=32){f.push(h);h=0}if(c===0){return f.concat(d)}for(g=0;g<d.length;g++){f.push(h|d[g]>>>c);h=d[g]<<(32-c)}b=d.length?d[d.length-1]:0;e=sjcl.bitArray.getPartial(b);f.push(sjcl.bitArray.partial(c+e&31,(c+e>32)?h:f.pop(),1));return f},_xor4:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};sjcl.codec.hex={fromBits:function(b){var c="",d,a;for(d=0;d<b.length;d++){c+=((b[d]|0)+0xf00000000000).toString(16).substr(4)}return c.substr(0,sjcl.bitArray.bitLength(b)/4)},toBits:function(d){var c,b=[],a;d=d.replace(/\s|0x/g,"");a=d.length;d=d+"00000000";for(c=0;c<d.length;c+=8){b.push(parseInt(d.substr(c,8),16)^0)}return sjcl.bitArray.clamp(b,a*4)}};

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
				onAddKey(origin, suffix, suffix === site.defaultSuffix, site.keys[suffix].key, site.keys[suffix].color);
			}
		}
	});
};

Model.validateOrigin = function (origin, onError) {
	// URL constructor doesn't work before Chrome 32
	var a = document.createElement('a');
	a.href = origin + '/';
	if (a.origin !== origin) {
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
	var color = 'rgb(192, 0, 46)';
	if (origin in Model.db) {
		var site = Model.db[origin];
		if (suffix in site.keys) {
			onError(Model.COLLISION_ERROR);
		} else {
			site.keys[suffix] = {key: key, color: color};
			var items = {};
			items['origin-' + origin] = site;
			chrome.storage.sync.set(items, function () {
				if (Model.checkStorageError(onError)) {
					delete site.keys[suffix];
				} else {
					onAddKey(origin, suffix, false, key, color);
					onSuccess();
				}
			});
		}
	} else {
		var site = {keys: {}, defaultSuffix: null};
		site.keys[suffix] = {key: key, color: 'rgb(192, 0, 46)'};
		site.defaultSuffix = suffix;
		site.rules = [];
		Model.db[origin] = site;
		var items = {};
		items['origin-' + origin] = site;
		chrome.storage.sync.set(items, function () {
			if (Model.checkStorageError(onError)) {
				delete Model.db[origin];
			} else {
				onAddSite(origin, site);
				onAddKey(origin, suffix, true, key, color);
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
	var h1 = document.createElement('h1');
	h1.className = 'origin';
	var a = document.createElement('a');
	a.href = origin + '/';
	a.target = '_blank';
	a.textContent = origin;
	h1.appendChild(a);
	var button = document.createElement('input');
	button.type = 'button';
	button.className = 'delete deleteSite';
	button.value = 'Delete';
	button.addEventListener('click', function (e) {
		Controller.removeSite(origin);
	});
	h1.appendChild(button);
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

View.onAddKey = function (origin, suffix, isDefault, key, color) {
	var div = document.getElementById('site-' + origin);
	var ul = div.querySelector('.keys');
	var li = document.createElement('li');
	li.id = 'key-' + origin + '/' + suffix;
	li.className = 'key';
	var label = document.createElement('label');
	label.className = 'default';
	var radio = document.createElement('input');
	radio.type = 'radio';
	radio.name = origin;
	radio.value = suffix;
	radio.checked = isDefault;
	radio.addEventListener('click', function (e) {
		e.preventDefault();
		Controller.setDefault(origin, suffix);
	});
	label.appendChild(radio);
	var span = document.createElement('span');
	span.className = 'suffix';
	span.style.color = color;
	span.textContent = suffix;
	label.appendChild(span);
	li.appendChild(label);
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
	var radio = li.querySelector('.default input');
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
