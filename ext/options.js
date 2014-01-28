// this is sjcl configured with:
// --compress=yui --without-all --with-bitArray --with-codecString --with-codecHex --with-sha256
var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};sjcl.bitArray={bitSlice:function(b,c,d){b=sjcl.bitArray._shiftRight(b.slice(c/32),32-(c&31)).slice(1);return(d===undefined)?b:sjcl.bitArray.clamp(b,d-c)},extract:function(c,d,f){var b,e=Math.floor((-d-f)&31);if((d+f-1^d)&-32){b=(c[d/32|0]<<(32-e))^(c[d/32+1|0]>>>e)}else{b=c[d/32|0]>>>e}return b&((1<<f)-1)},concat:function(c,a){if(c.length===0||a.length===0){return c.concat(a)}var d,e,f=c[c.length-1],b=sjcl.bitArray.getPartial(f);if(b===32){return c.concat(a)}else{return sjcl.bitArray._shiftRight(a,b,f|0,c.slice(0,c.length-1))}},bitLength:function(d){var c=d.length,b;if(c===0){return 0}b=d[c-1];return(c-1)*32+sjcl.bitArray.getPartial(b)},clamp:function(d,b){if(d.length*32<b){return d}d=d.slice(0,Math.ceil(b/32));var c=d.length;b=b&31;if(c>0&&b){d[c-1]=sjcl.bitArray.partial(b,d[c-1]&2147483648>>(b-1),1)}return d},partial:function(b,a,c){if(b===32){return a}return(c?a|0:a<<(32-b))+b*0x10000000000},getPartial:function(a){return Math.round(a/0x10000000000)||32},equal:function(e,d){if(sjcl.bitArray.bitLength(e)!==sjcl.bitArray.bitLength(d)){return false}var c=0,f;for(f=0;f<e.length;f++){c|=e[f]^d[f]}return(c===0)},_shiftRight:function(d,c,h,f){var g,b=0,e;if(f===undefined){f=[]}for(;c>=32;c-=32){f.push(h);h=0}if(c===0){return f.concat(d)}for(g=0;g<d.length;g++){f.push(h|d[g]>>>c);h=d[g]<<(32-c)}b=d.length?d[d.length-1]:0;e=sjcl.bitArray.getPartial(b);f.push(sjcl.bitArray.partial(c+e&31,(c+e>32)?h:f.pop(),1));return f},_xor4:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};sjcl.codec.utf8String={fromBits:function(a){var b="",e=sjcl.bitArray.bitLength(a),d,c;for(d=0;d<e/8;d++){if((d&3)===0){c=a[d/4]}b+=String.fromCharCode(c>>>24);c<<=8}return decodeURIComponent(escape(b))},toBits:function(d){d=unescape(encodeURIComponent(d));var a=[],c,b=0;for(c=0;c<d.length;c++){b=b<<8|d.charCodeAt(c);if((c&3)===3){a.push(b);b=0}}if(c&3){a.push(sjcl.bitArray.partial(8*(c&3),b))}return a}};sjcl.codec.hex={fromBits:function(b){var c="",d,a;for(d=0;d<b.length;d++){c+=((b[d]|0)+0xf00000000000).toString(16).substr(4)}return c.substr(0,sjcl.bitArray.bitLength(b)/4)},toBits:function(d){var c,b=[],a;d=d.replace(/\s|0x/g,"");a=d.length;d=d+"00000000";for(c=0;c<d.length;c+=8){b.push(parseInt(d.substr(c,8),16)^0)}return sjcl.bitArray.clamp(b,a*4)}};sjcl.hash.sha256=function(a){if(!this._key[0]){this._precompute()}if(a){this._h=a._h.slice(0);this._buffer=a._buffer.slice(0);this._length=a._length}else{this.reset()}};sjcl.hash.sha256.hash=function(a){return(new sjcl.hash.sha256()).update(a).finalize()};sjcl.hash.sha256.prototype={blockSize:512,reset:function(){this._h=this._init.slice(0);this._buffer=[];this._length=0;return this},update:function(f){if(typeof f==="string"){f=sjcl.codec.utf8String.toBits(f)}var e,a=this._buffer=sjcl.bitArray.concat(this._buffer,f),d=this._length,c=this._length=d+sjcl.bitArray.bitLength(f);for(e=512+d&-512;e<=c;e+=512){this._block(a.splice(0,16))}return this},finalize:function(){var c,a=this._buffer,d=this._h;a=sjcl.bitArray.concat(a,[sjcl.bitArray.partial(1,1)]);for(c=a.length+2;c&15;c++){a.push(0)}a.push(Math.floor(this._length/0x100000000));a.push(this._length|0);while(a.length){this._block(a.splice(0,16))}this.reset();return d},_init:[],_key:[],_precompute:function(){var d=0,c=2,b;function a(e){return(e-Math.floor(e))*0x100000000|0}outer:for(;d<64;c++){for(b=2;b*b<=c;b++){if(c%b===0){continue outer}}if(d<8){this._init[d]=a(Math.pow(c,1/2))}this._key[d]=a(Math.pow(c,1/3));d++}},_block:function(q){var e,f,t,s,u=q.slice(0),j=this._h,c=this._key,r=j[0],p=j[1],o=j[2],n=j[3],m=j[4],l=j[5],g=j[6],d=j[7];for(e=0;e<64;e++){if(e<16){f=u[e]}else{t=u[(e+1)&15];s=u[(e+14)&15];f=u[e&15]=((t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(s>>>17^s>>>19^s>>>10^s<<15^s<<13)+u[e&15]+u[(e+9)&15])|0}f=(f+d+(m>>>6^m>>>11^m>>>25^m<<26^m<<21^m<<7)+(g^m&(l^g))+c[e]);d=g;g=l;l=m;m=n+f|0;n=o;o=p;p=r;r=(f+((p&o)^(n&(p^o)))+(p>>>2^p>>>13^p>>>22^p<<30^p<<19^p<<10))|0}j[0]=j[0]+r|0;j[1]=j[1]+p|0;j[2]=j[2]+o|0;j[3]=j[3]+n|0;j[4]=j[4]+m|0;j[5]=j[5]+l|0;j[6]=j[6]+g|0;j[7]=j[7]+d|0}};

var MAX_ERROR = 1;

var Model = {
	SITE_KEY_PATTERN: /^origin-(.*)$/,
	FINGERPRINT_PATTERN: /^[0-9a-f]{64}$/,

	STORAGE_ERROR: MAX_ERROR++,
	ORIGIN_NORMALIZE_ERROR: MAX_ERROR++,
	FINGERPRINT_FORMAT_ERROR: MAX_ERROR++,
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
			for (var fingerprint in site.keys) {
				onAddKey(origin, fingerprint, fingerprint === site.defaultFingerprint, site.keys[fingerprint]);
			}
		}
	});
};

Model.computeFingerprint = function (secret) {
	return sjcl.codec.hex.fromBits(sjcl.hash.sha256(secret));
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

Model.validateSecret = function (secret, onError) {
	switch (sjcl.bitArray.bitLength(secret)) {
	case 128:
	case 192:
	case 256:
		return false;
	default:
		onError(Model.KEY_LENGTH_ERROR);
		return true;
	}
};

Model.add = function (origin, fingerprint, name, secret, color, passphrase, onAddSite, onAddKey, onSuccess, onError) {
	if (Model.validateOrigin(origin, onError)) return;
	if (Model.validateFingerprint(fingerprint, onError)) return;
	if (Model.validateSecret(secret, onError)) return;
	if (origin in Model.db) {
		var site = Model.db[origin];
		if (fingerprint in site.keys) {
			onError(Model.COLLISION_ERROR);
		} else {
			var key = {
				name: name,
				secret: secret,
				color: color,
				passphrase: passphrase
			};
			site.keys[fingerprint] = key;
			var items = {};
			items['origin-' + origin] = site;
			chrome.storage.sync.set(items, function () {
				if (Model.checkStorageError(onError)) {
					delete site.keys[fingerprint];
				} else {
					onAddKey(origin, fingerprint, false, key);
					onSuccess();
				}
			});
		}
	} else {
		var site = {keys: {}, defaultSuffix: null};
		var key = {
			name: name,
			secret: secret,
			color: color,
			passphrase: passphrase
		};
		site.keys[fingerprint] = key;
		site.defaultSuffix = fingerprint;
		site.rules = [];
		Model.db[origin] = site;
		var items = {};
		items['origin-' + origin] = site;
		chrome.storage.sync.set(items, function () {
			if (Model.checkStorageError(onError)) {
				delete Model.db[origin];
			} else {
				onAddSite(origin, site);
				onAddKey(origin, fingerprint, true, key);
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

Model.removeKey = function (origin, fingerprint, onRemoveKey, onSuccess, onError) {
	if (origin in Model.db) {
		var site = Model.db[origin];
		if (fingerprint === site.defaultSuffix) {
			onError(Model.REMOVE_DEFAULT_ERROR);
		} else if (fingerprint in site.keys) {
			var key = site.keys[fingerprint];
			delete site.keys[fingerprint];
			var items = {};
			items['origin-' + origin] = site;
			chrome.storage.sync.set(items, function () {
				if (Model.checkStorageError(onError)) {
					site.keys[fingerprint] = key;
				} else {
					onRemoveKey(origin, fingerprint);
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

Model.setDefault = function (origin, fingerprint, onSetDefault, onSuccess, onError) {
	if (origin in Model.db) {
		var site = Model.db[origin];
		if (fingerprint in site.keys) {
			var oldSuffix = site.defaultSuffix;
			site.defaultSuffix = fingerprint;
			var items = {};
			items['origin-' + origin] = site;
			chrome.storage.sync.set(items, function () {
				if (Model.checkStorageError(onError)) {
					site.defaultSuffix = oldSuffix;
				} else {
					onSetDefault(origin, fingerprint);
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
	nameField: null,
	colorField: null,
	passphraseField: null,
	list: null
};

View.init = function () {
	// in init() because not all error codes are declared until the bottom
	View.errorMessages[Model.STORAGE_ERROR] = 'Error saving change';
	View.errorMessages[Model.ORIGIN_NORMALIZE_ERROR] = 'Website must be specified as an origin';
	// View.errorMessages[Model.FINGERPRINT_FORMAT_ERROR] is not a user-facing error
	View.errorMessages[Model.KEY_LENGTH_ERROR] = 'Key must be 128, 192, or 256 bits';
	View.errorMessages[Model.COLLISION_ERROR] = 'You already have that key on that site';
	View.errorMessages[Model.REMOVE_DEFAULT_ERROR] = 'Cannot delete a site\'s default key';
	View.errorMessages[Model.KEY_REFERENCE_ERROR] = 'The specified key does not exist';
	View.errorMessages[Model.SITE_REFERENCE_ERROR] = 'The specified site does not exist';
	View.errorMessages[Controller.IMPORT_FORMAT_ERROR] = 'Malformed key specification';

	View.messageDisplay = document.getElementById('messageDisplay');
	View.importForm = document.getElementById('importForm');
	View.importField = document.getElementById('importField');
	View.generateForm = document.getElementById('generateForm');
	View.originField = document.getElementById('originField');
	View.nameField = document.getElementById('nameField');
	View.colorField = document.getElementById('colorField');
	View.passphraseField = document.getElementById('passphraseField');
	View.list = document.getElementById('list');

	View.importForm.addEventListener('submit', function (e) {
		e.preventDefault();
		Controller.importKey(importField.value);
	});

	View.generateForm.addEventListener('submit', function (e) {
		e.preventDefault();
		Controller.generateKey(originField.value, nameField.value);
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
