var Compat = {
	createShadowRoot: function (e) { return e.webkitCreateShadowRoot(); },
	afterSubmit: function (f) { setTimeout(f, 0); },
	getInnerText: function (e) { return e.innerText; }
};

var Content = {};

Content.within = function () {
	function onSetup(e) {
		setup(e.target.contentWindow);
	}

	function onShimProp(e) {
		var node = e.target;
		var name = e.detail.name;
		var value = e.detail.value;
		Object.defineProperty(node, name, {
			get: function () {
				return value;
			},
			set: function (v) {
				value = v;
				var event = new CustomEvent('zerokit-prop-set-' + name, {detail: value});
				node.dispatchEvent(event);
			}
		});
		node.addEventListener('zerokit-set-prop-' + name, function (e) {
			value = e.detail;
		});
	}

	function onShimMethod(e) {
		// no args or return value lol
		var node = e.target;
		var name = e.detail.name;
		node[name] = function () {
			var event = new Event('zerokit-method-call-' + name);
			node.dispatchEvent(event);
		};
	}

	function youCantTouchSelectionAnymore() {
		console.warn('ignoring selection manipulation');
	}

	function setup(win) {
		win.addEventListener('zerokit-add-listeners', onSetup, true);
		win.addEventListener('zerokit-shim-prop', onShimProp, true);
		win.addEventListener('zerokit-shim-method', onShimMethod, true);
		// caveat: you can't touch selection anymore
		win.Selection.prototype.removeAllRanges = youCantTouchSelectionAnymore;
		win.Selection.prototype.addRange = youCantTouchSelectionAnymore;
	}

	setup(window);
};

Content.init = function () {
	var script = document.createElement('script');
	script.textContent = '(' + Content.within + ')();';
	document.documentElement.appendChild(script);
};

Content.propagate = function (iframe) {
	var event = new Event('zerokit-add-listeners', false, false);
	iframe.dispatchEvent(event);
};

Content.shimProp = function (node, name, value, handler) {
	node.addEventListener('zerokit-prop-set-' + name, function (e) {
		handler(e.detail);
	});
	var event = new CustomEvent('zerokit-shim-prop', {detail: {name: name, value: value}});
	node.dispatchEvent(event);
	return function (v) {
		var event = new CustomEvent('zerokit-set-prop-' + name, {detail: v});
		node.dispatchEvent(event);
	};
};

Content.shimMethod = function (node, name, handler) {
	node.addEventListener('zerokit-method-call-' + name, function (e) {
		handler();
	});
	var event = new CustomEvent('zerokit-shim-method', {detail: {name: name}});
	node.dispatchEvent(event);
};

// this is from from http://crypto.stanford.edu/sjcl/sjcl.js
// narrowed down to bitArray, base64, utf8String, aes, and ccm
var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};sjcl.bitArray={bitSlice:function(a,b,c){a=sjcl.bitArray._shiftRight(a.slice(b/32),32-(b&31)).slice(1);return void 0===c?a:sjcl.bitArray.clamp(a,c-b)},extract:function(a,b,c){var e=Math.floor(-b-c&31);return((b+c-1^b)&-32?a[b/32|0]<<32-e^a[b/32+1|0]>>>e:a[b/32|0]>>>e)&(1<<c)-1},concat:function(a,b){if(0===a.length||0===b.length)return a.concat(b);var c=a[a.length-1],e=sjcl.bitArray.getPartial(c);return 32===e?a.concat(b):sjcl.bitArray._shiftRight(b,e,c|0,a.slice(0,a.length-1))},bitLength:function(a){var b=a.length;return 0===b?0:32*(b-1)+sjcl.bitArray.getPartial(a[b-1])},clamp:function(a,b){if(32*a.length<b)return a;a=a.slice(0,Math.ceil(b/32));var c=a.length;b&=31;0<c&&b&&(a[c-1]=sjcl.bitArray.partial(b,a[c-1]&2147483648>>b-1,1));return a},partial:function(a,b,c){return 32===a?b:(c?b|0:b<<32-a)+1099511627776*a},getPartial:function(a){return Math.round(a/1099511627776)||32},equal:function(a,b){if(sjcl.bitArray.bitLength(a)!==sjcl.bitArray.bitLength(b))return!1;var c=0,e;for(e=0;e<a.length;e++)c|=a[e]^b[e];return 0===c},_shiftRight:function(a,b,c,e){var d;d=0;for(void 0===e&&(e=[]);32<=b;b-=32)e.push(c),c=0;if(0===b)return e.concat(a);for(d=0;d<a.length;d++)e.push(c|a[d]>>>b),c=a[d]<<32-b;d=a.length?a[a.length-1]:0;a=sjcl.bitArray.getPartial(d);e.push(sjcl.bitArray.partial(b+a&31,32<b+a?c:e.pop(),1));return e},_xor4:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};sjcl.codec.base64={_chars:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",fromBits:function(a,b,c){var e="",d=0,f=sjcl.codec.base64._chars,g=0,h=sjcl.bitArray.bitLength(a);c&&(f=f.substr(0,62)+"-_");for(c=0;6*e.length<h;)e+=f.charAt((g^a[c]>>>d)>>>26),6>d?(g=a[c]<<6-d,d+=26,c++):(g<<=6,d-=6);for(;e.length&3&&!b;)e+="=";return e},toBits:function(a,b){a=a.replace(/\s|=/g,"");var c=[],e,d=0,f=sjcl.codec.base64._chars,g=0,h;b&&(f=f.substr(0,62)+"-_");for(e=0;e<a.length;e++){h=f.indexOf(a.charAt(e));if(0>h)throw new sjcl.exception.invalid("this isn't base64!");26<d?(d-=26,c.push(g^h>>>d),g=h<<32-d):(d+=6,g^=h<<32-d)}d&56&&c.push(sjcl.bitArray.partial(d&56,g,1));return c}};sjcl.codec.base64url={fromBits:function(a){return sjcl.codec.base64.fromBits(a,1,1)},toBits:function(a){return sjcl.codec.base64.toBits(a,1)}};sjcl.codec.utf8String={fromBits:function(a){var b="",c=sjcl.bitArray.bitLength(a),e,d;for(e=0;e<c/8;e++)0===(e&3)&&(d=a[e/4]),b+=String.fromCharCode(d>>>24),d<<=8;return decodeURIComponent(escape(b))},toBits:function(a){a=unescape(encodeURIComponent(a));var b=[],c,e=0;for(c=0;c<a.length;c++)e=e<<8|a.charCodeAt(c),3===(c&3)&&(b.push(e),e=0);c&3&&b.push(sjcl.bitArray.partial(8*(c&3),e));return b}};sjcl.cipher.aes=function(a){this._tables[0][0][0]||this._precompute();var b,c,e,d,f=this._tables[0][4],g=this._tables[1];b=a.length;var h=1;if(4!==b&&6!==b&&8!==b)throw new sjcl.exception.invalid("invalid aes key size");this._key=[e=a.slice(0),d=[]];for(a=b;a<4*b+28;a++){c=e[a-1];if(0===a%b||8===b&&4===a%b)c=f[c>>>24]<<24^f[c>>16&255]<<16^f[c>>8&255]<<8^f[c&255],0===a%b&&(c=c<<8^c>>>24^h<<24,h=h<<1^283*(h>>7));e[a]=e[a-b]^c}for(b=0;a;b++,a--)c=e[b&3?a:a-4],d[b]=4>=a||4>b?c:g[0][f[c>>>24]]^g[1][f[c>>16&255]]^g[2][f[c>>8&255]]^g[3][f[c&255]]};sjcl.cipher.aes.prototype={encrypt:function(a){return this._crypt(a,0)},decrypt:function(a){return this._crypt(a,1)},_tables:[[[],[],[],[],[]],[[],[],[],[],[]]],_precompute:function(){var a=this._tables[0],b=this._tables[1],c=a[4],e=b[4],d,f,g,h=[],k=[],m,p,l,n;for(d=0;256>d;d++)k[(h[d]=d<<1^283*(d>>7))^d]=d;for(f=g=0;!c[f];f^=m||1,g=k[g]||1)for(l=g^g<<1^g<<2^g<<3^g<<4,l=l>>8^l&255^99,c[f]=l,e[l]=f,p=h[d=h[m=h[f]]],n=16843009*p^65537*d^257*m^16843008*f,p=257*h[l]^16843008*l,d=0;4>d;d++)a[d][f]=p=p<<24^p>>>8,b[d][l]=n=n<<24^n>>>8;for(d=0;5>d;d++)a[d]=a[d].slice(0),b[d]=b[d].slice(0)},_crypt:function(a,b){if(4!==a.length)throw new sjcl.exception.invalid("invalid aes block size");var c=this._key[b],e=a[0]^c[0],d=a[b?3:1]^c[1],f=a[2]^c[2],g=a[b?1:3]^c[3],h,k,m,p=c.length/4-2,l,n=4,v=[0,0,0,0];h=this._tables[b];var q=h[0],r=h[1],s=h[2],t=h[3],u=h[4];for(l=0;l<p;l++)h=q[e>>>24]^r[d>>16&255]^s[f>>8&255]^t[g&255]^c[n],k=q[d>>>24]^r[f>>16&255]^s[g>>8&255]^t[e&255]^c[n+1],m=q[f>>>24]^r[g>>16&255]^s[e>>8&255]^t[d&255]^c[n+2],g=q[g>>>24]^r[e>>16&255]^s[d>>8&255]^t[f&255]^c[n+3],n+=4,e=h,d=k,f=m;for(l=0;4>l;l++)v[b?3&-l:l]=u[e>>>24]<<24^u[d>>16&255]<<16^u[f>>8&255]<<8^u[g&255]^c[n++],h=e,e=d,d=f,f=g,g=h;return v}};sjcl.mode.ccm={name:"ccm",encrypt:function(a,b,c,e,d){var f,g=b.slice(0),h=sjcl.bitArray,k=h.bitLength(c)/8,m=h.bitLength(g)/8;d=d||64;e=e||[];if(7>k)throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");for(f=2;4>f&&m>>>8*f;f++);f<15-k&&(f=15-k);c=h.clamp(c,8*(15-f));b=sjcl.mode.ccm._computeTag(a,b,c,e,d,f);g=sjcl.mode.ccm._ctrMode(a,g,c,b,d,f);return h.concat(g.data,g.tag)},decrypt:function(a,b,c,e,d){d=d||64;e=e||[];var f=sjcl.bitArray,g=f.bitLength(c)/8,h=f.bitLength(b),k=f.clamp(b,h-d),m=f.bitSlice(b,h-d),h=(h-d)/8;if(7>g)throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");for(b=2;4>b&&h>>>8*b;b++);b<15-g&&(b=15-g);c=f.clamp(c,8*(15-b));k=sjcl.mode.ccm._ctrMode(a,k,c,m,d,b);a=sjcl.mode.ccm._computeTag(a,k.data,c,e,d,b);if(!f.equal(k.tag,a))throw new sjcl.exception.corrupt("ccm: tag doesn't match");return k.data},_computeTag:function(a,b,c,e,d,f){var g=[],h=sjcl.bitArray,k=h._xor4;d/=8;if(d%2||4>d||16<d)throw new sjcl.exception.invalid("ccm: invalid tag length");if(4294967295<e.length||4294967295<b.length)throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data");f=[h.partial(8,(e.length?64:0)|d-2<<2|f-1)];f=h.concat(f,c);f[3]|=h.bitLength(b)/8;f=a.encrypt(f);if(e.length)for(c=h.bitLength(e)/8,65279>=c?g=[h.partial(16,c)]:4294967295>=c&&(g=h.concat([h.partial(16,65534)],[c])),g=h.concat(g,e),e=0;e<g.length;e+=4)f=a.encrypt(k(f,g.slice(e,e+4).concat([0,0,0])));for(e=0;e<b.length;e+=4)f=a.encrypt(k(f,b.slice(e,e+4).concat([0,0,0])));return h.clamp(f,8*d)},_ctrMode:function(a,b,c,e,d,f){var g,h=sjcl.bitArray;g=h._xor4;var k=b.length,m=h.bitLength(b);c=h.concat([h.partial(8,f-1)],c).concat([0,0,0]).slice(0,4);e=h.bitSlice(g(e,a.encrypt(c)),0,d);if(!k)return{tag:e,data:[]};for(g=0;g<k;g+=4)c[3]++,d=a.encrypt(c),b[g]^=d[0],b[g+1]^=d[1],b[g+2]^=d[2],b[g+3]^=d[3];return{tag:e,data:h.clamp(b,m)}}};

var Crypto = {
	keys: {},
	defaultSuffix: null,
	cipher: sjcl.cipher.aes,
	mode: sjcl.mode.ccm,
	ivLength: 4
};

Crypto.getKey = function (suffix) {
	if (!(suffix in Crypto.keys)) throw new Error('unknown suffix', suffix);
	return Crypto.keys[suffix];
};

Crypto.encrypt = function (key, data, adata) {
	var pt = sjcl.codec.utf8String.toBits(data);
	var iv = Array.prototype.slice.call(window.crypto.getRandomValues(new Uint32Array(Crypto.ivLength)));
	var ct = Crypto.mode.encrypt(new Crypto.cipher(key), pt, iv, sjcl.codec.utf8String.toBits(adata));
	return sjcl.codec.base64.fromBits(iv.concat(ct));
};

Crypto.decrypt = function (key, data, adata) {
	var ct = sjcl.codec.base64.toBits(data);
	var iv = ct.splice(0, Crypto.ivLength);
	var pt = Crypto.mode.decrypt(new Crypto.cipher(key), ct, iv, sjcl.codec.utf8String.toBits(adata));
	return sjcl.codec.utf8String.fromBits(pt);
};

var Scanner = function (impl, root) {
	this.root = root;
	this.iter = impl.createNodeIterator(root, NodeFilter.SHOW_TEXT);
	this.u = 0;
	this.v = 0;
	this.next();
};

Scanner.getNodeLength = function (node) {
	// simplified implementation of
	// http://dom.spec.whatwg.org/#concept-node-length
	// supporting only Element and CharacterData Nodes
	if (node.nodeType === Document.TYPE_ELEMENT) {
		return node.childNodes.length;
	} else {
		return node.length;
	}
};

Scanner.prototype.next = function () {
	this.n = this.iter.nextNode();
	this.u = this.v;
	this.v = this.u + this.n.length;
};

Scanner.prototype.setStart = function (range, index) {
	while (this.n) {
		if (index >= this.u && index < this.v) return range.setStart(this.n, index - this.u);
		this.next();
	}
	throw new Error('index out of bounds', index);
};

Scanner.prototype.setEnd = function (range, index) {
	while (this.n) {
		if (index > this.u && index <= this.v) return range.setEnd(this.n, index - this.u);
		this.next();
	}
	throw new Error('index out of bounds', index);
};

Scanner.prototype.sink = function (range, light) {
	// 1. sink from offsets to containers
	if (range.startOffset !== 0) return;
	if (range.endOffset !== Scanner.getNodeLength(range.endContainer)) return;

	// 2. sink from containers to common ancestor
	var ancestor = range.commonAncestorContainer;
	var startContainer = range.startContainer;
	while (startContainer !== ancestor) {
		if (startContainer.previousSibling) return;
		startContainer = startContainer.parentNode;
	}
	var endContainer = range.endContainer;
	while (endContainer !== ancestor) {
		if (endContainer.nextSibling) return;
		endContainer = endContainer.parentNode;
	}

	if (light) {
		// 3a. done
		range.selectNodeContents(ancestor);
	} else {
		// 3b. sink from common ancestor to first ancestor with sibling
		while (ancestor !== this.root) {
			if (ancestor.previousSibling) break;
			if (ancestor.nextSibling) break;
			ancestor = ancestor.parentNode;
		}

		// 4b. done
		range.selectNode(ancestor);
	}
};

var Tags = {
	TAG_PATTERN: /(?:@|#|\/r\/|\/u\/)\w+/g,
	TAG_TEST_PATTERN: /^(?:@|#|\/r\/|\/u\/)\w+$/, // the above with ^...$
	// remember to change Codec.CODE_PATTERN too
};

Tags.extractTags = function (message) {
	var tags = [];
	var seen = {};
	var match;
	while (match = Tags.TAG_PATTERN.exec(message)) {
		var tag = match[0];
		if (tag in seen) continue;
		tags.push(tag);
	}
	return tags.join(',');
};

Tags.readTags = function (impl, scanner, text, match) {
	var start = match.index + 9 + match[1].length + 1;
	var end = start + match[2].length;
	var tags = [];
	while (start < end) {
		var comma = text.indexOf(',', start);
		if (comma === -1 || comma > end) comma = end;
		var tag = text.slice(start, comma);
		if (!Tags.TAG_TEST_PATTERN.test(tag)) continue;
		var range = impl.createRange();
		scanner.setStart(range, start);
		scanner.setEnd(range, comma);
		scanner.sink(range);
		tags.push([tag, range.cloneContents()]);
		start = comma + 1;
	}
	return tags;
};

Tags.insertTags = function (impl, message, tags) {
	// might have matched CODE_PATTERN[2] but not any TAG_PATTERN
	if (!tags.length) return impl.createTextNode(message);
	var frags = [];
	var map = {};
	for (var i = 0; i < tags.length; i++) {
		frags.push(tags[i][0] + '\\b');
		map[tags[i][0]] = tags[i][1];
	}
	var pattern = new RegExp(frags.join('|'), 'g');
	var result = impl.createDocumentFragment();
	var last = 0;
	var match;
	while (match = pattern.exec(message)) {
		if (match.index > last) {
			result.appendChild(impl.createTextNode(message.slice(last, match.index)));
		}
		result.appendChild(map[match[0]].cloneNode(true)); // lol chrome defaults to (false)
		last = match.index + match[0].length;
	}
	if (last < message.length) {
		result.appendChild(impl.createTextNode(message.slice(last)));
	}
	return result;
};

var Codec = {
	CODE_PATTERN: /=\?zerokit(\w*)\?([\w@#\/,]*)\?([A-Za-z0-9+\/=]*)\?=/g
};

Codec.encode = function (suffix, message) {
	if (message === '') return '';
	var tags = Tags.extractTags(message);
	var data = Crypto.encrypt(Crypto.getKey(suffix), message, tags);
	return '=?zerokit' + suffix + '?' + tags + '?' + data + '?=';
};

Codec.decode = function (suffix, tags, data) {
	return Crypto.decrypt(Crypto.getKey(suffix), data, tags);
};

var Rewriter = {
	FAST_FAIL_QUERY: '=?zerokit'
};

Rewriter.fastFail = function (text) {
	var index = text.indexOf(Rewriter.FAST_FAIL_QUERY);
	if (index === -1) return true;
	Codec.CODE_PATTERN.lastIndex = index;
	return false;
};

Rewriter.checkBlacklist = function (node) {
	if (!node) return false;
	if (node.nodeType === Document.ELEMENT_NODE) {
		if ('zerokitReplaced' in node) return true;
		if ('zerokitUpdateContent' in node) return true;
		if (node.tagName.toLowerCase() === 'textarea') return true;
	}
	return Rewriter.checkBlacklist(node.parentNode);
};

Rewriter.checkRangeEndpoints = function (range) {
	var startElement = range.startContainer;
	if (startElement.nodeType !== Document.ELEMENT_NODE) startElement = startElement.parentNode;
	var endElement = range.endContainer;
	if (endElement.nodeType !== Document.ELEMENT_NODE) endElement = endElement.parentNode;
	return startElement === endElement;
};

Rewriter.findCodes = function (impl, node) {
	// caveat: uses comments and processing instructions
	var text = node.textContent;
	if (Rewriter.fastFail(text)) return null;
	var codes = [];
	var scanner = new Scanner(impl, node);
	var match;
	while (match = Codec.CODE_PATTERN.exec(text)) {
		try {
			var range = impl.createRange();
			scanner.setStart(range, match.index);
			if (Rewriter.checkBlacklist(range.startContainer)) continue;
			var messageText = Codec.decode(match[1], match[2], match[3]);
			var messageNode;
			if (match[2]) {
				var tags = Tags.readTags(impl, scanner, text, match);
				messageNode = Tags.insertTags(impl, messageText, tags);
			} else {
				messageNode = impl.createTextNode(messageText);
			}
			scanner.setEnd(range, match.index + match[0].length);
			scanner.sink(range, true);
			if (!Rewriter.checkRangeEndpoints(range)) throw new Error('aborting suspicious range');
			codes.push([range, messageNode]);
		} catch (e) {
			console.warn(e);
		}
	}
	return codes;
};

Rewriter.repaceCodes = function (impl, codes) {
	for (var i = 0; i < codes.length; i++) {
		var range = codes[i][0];
		var messageNode = codes[i][1];
		// caveat: this doesn't work in <title>
		var span = impl.createElement('span');
		span.zerokitReplaced = true;
		range.surroundContents(span);
		var shadow = Compat.createShadowRoot(span);
		shadow.applyAuthorStyles = true;
		shadow.resetStyleInheritance = false;
		shadow.appendChild(messageNode);
	}
};

Rewriter.rewriteMarkup = function (impl, node) {
	var codes = Rewriter.findCodes(impl, node);
	if (codes) Rewriter.repaceCodes(impl, codes);
};

Rewriter.replacer = function (code, suffix, tags, data) {
	try {
		return Codec.decode(suffix, tags, data);
	} catch (e) {
		console.warn(e);
		return code;
	}
};

Rewriter.processString = function (str) {
	return str.replace(Codec.CODE_PATTERN, Rewriter.replacer);
};

var Widgets = {
	WIDGET_SELECTOR: 'form,input,textarea,[contenteditable],iframe',
	adapters: {}
};

Widgets.AbstractAdapter = function (e) {
	this.node = e;
};

Widgets.Styled = function (e) {
	Widgets.AbstractAdapter.call(this, e);
	this.enabled = true;
	this.node.style.outlineOffset = '-1px';
	this.node.style.outlineWidth = '1px';
	this.node.style.outlineStyle = 'solid';
	this.updateStyle();
};
Widgets.Styled.prototype = Object.create(Widgets.AbstractAdapter.prototype);
Widgets.Styled.prototype.constructor = Widgets.Styled;

Widgets.Styled.prototype.enable = function () {
	this.enabled = true;
	this.updateStyle();
};

Widgets.Styled.prototype.disable = function () {
	this.enabled = false;
	this.updateStyle();
};

Widgets.Styled.prototype.toggle = function () {
	if (this.enabled) this.disable();
	else this.enable();
};

Widgets.Styled.prototype.updateStyle = function () {
	this.node.style.outlineColor = this.enabled ? '#c00040' : '#80c000';
};

Widgets.adapters.Form = function (e) {
	Widgets.AbstractAdapter.call(this, e);
	this.node.addEventListener('submit', this.onSubmit.bind(this));
	Content.shimMethod(this.node, 'submit', this.submit.bind(this));
};
Widgets.adapters.Form.prototype = Object.create(Widgets.AbstractAdapter.prototype);
Widgets.adapters.Form.prototype.constructor = Widgets.adapters.Form;

Widgets.adapters.Form.prototype.onSubmit = function (e) {
	if (e.defaultPrevented) return;
	var undodge = this.dodge();
	if (undodge) Compat.afterSubmit(undodge);
};

Widgets.adapters.Form.prototype.submit = function () {
	var undodge = this.dodge();
	this.node.submit();
	if (undodge) Compat.afterSubmit(undodge);
};

Widgets.adapters.Form.prototype.dodge = function () {
	var undodges = [];
	for (var i = 0; i < this.node.elements.length; i++) {
		var elem = this.node.elements[i];
		if ('zerokitDodge' in elem) undodges.push(elem.zerokitDodge());
	}
	if (!undodges.length) return null;
	return function () {
		for (var i = 0; i < undodges.length; i++) {
			undodges[i]();
		}
	};
};

Widgets.adapters.Input = function (e) {
	Widgets.Styled.call(this, e);
	this.publicValue = this.node.value;
	this.setValue = Content.shimProp(this.node, 'value', this.publicValue, this.onValueSet.bind(this));
	this.node.value = Rewriter.processString(this.node.value);
	this.node.zerokitDodge = this.dodge.bind(this);
	this.node.zerokitInputEarly = this.onInputEarly.bind(this);
	this.node.addEventListener('keydown', this.onKeydown.bind(this), true);
};
Widgets.adapters.Input.prototype = Object.create(Widgets.Styled.prototype);
Widgets.adapters.Input.prototype.constructor = Widgets.adapters.Input;

Widgets.adapters.Input.prototype.onValueSet = function (v) {
	var cipher = v;
	var plain = Rewriter.processString(cipher);
		this.node.value = plain;
	if (this.enabled) {
		this.publicValue = cipher;
	} else {
		this.publicValue = plain;
		this.setValue(plain);
	}
};

Widgets.adapters.Input.prototype.onInputEarly = function () {
	var plain = this.node.value;
	if (this.enabled) {
		var cipher = Codec.encode(Crypto.defaultSuffix, plain);
		this.publicValue = cipher;
		this.setValue(cipher);
	} else {
		this.publicValue = plain;
		this.setValue(plain);
	}
};

Widgets.adapters.Input.prototype.onKeydown = function (e) {
	if (e.keyCode === 32 && e.ctrlKey) {
		e.preventDefault();
		e.stopPropagation();
		this.toggle();
	}
};

Widgets.adapters.Input.prototype.enable = function () {
	Widgets.Styled.prototype.enable.call(this);
	var plain = this.node.value;
	var cipher = Codec.encode(Crypto.defaultSuffix, plain);
	this.publicValue = cipher;
	this.setValue(cipher);
	this.node.zerokitDodge = this.dodge.bind(this);
};

Widgets.adapters.Input.prototype.disable = function () {
	Widgets.Styled.prototype.disable.call(this);
	var plain = this.node.value;
	this.publicValue = plain;
	this.setValue(plain);
	delete this.node.zerokitDodge;
};

Widgets.adapters.Input.prototype.dodge = function () {
	var privateValue = this.node.value;
	this.node.value = this.publicValue;
	return function () {
		this.node.value = privateValue;
	}.bind(this);
};

Widgets.adapters.TextArea = function (e) {
	Widgets.adapters.Input.call(this, e);
};
Widgets.adapters.TextArea.prototype = Object.create(Widgets.adapters.Input.prototype);
Widgets.adapters.TextArea.prototype.constructor = Widgets.adapters.TextArea;

Widgets.adapters.ContentEditable = function (e) {
	Widgets.Styled.call(this, e);
	this.node.zerokitUpdateContent = this.updateContent.bind(this);
	this.node.addEventListener('focus', this.onFocus.bind(this));

	var impl = this.node.ownerDocument;
	this.delegate = impl.createElement('textarea');
	this.delegate.dataset.zerokitStyle = 'widget';
	this.delegate.style.cssText = 'display:block;margin:0;border:medium none;padding:0;width:100%;height:100%;background:transparent;font:inherit;color:inherit;text-decoration:inherit;outline:none;resize:none;';
	this.delegate.value = Rewriter.processString(Compat.getInnerText(this.node));
	this.delegate.addEventListener('input', this.onInput.bind(this), true);
	this.delegate.addEventListener('keyup', Widgets.adapters.ContentEditable.stopEvent);
	this.delegate.addEventListener('keydown', Widgets.adapters.ContentEditable.stopEvent);
	this.delegate.addEventListener('keypress', Widgets.adapters.ContentEditable.stopEvent);

	// set explicit height for 100% to work, which caveat: might be undesirable
	var style = impl.defaultView.getComputedStyle(this.node);
	if (this.node === impl.body) {
		// if this is the <body>, maximize height
		var margin = style.margin;
		this.node.style.margin = '0';
		this.delegate.style.margin = margin;
		impl.documentElement.style.height = '100%';
		this.node.style.boxSizing = 'border-box';
		this.node.style.height = '100%';
	} else if (style.height === 'auto') {
		var offsetHeight = this.node.offsetHeight;
		if (offsetHeight > 0) {
			// lock in current height
			this.node.style.boxSizing = 'border-box';
			this.node.style.height = offsetHeight + 'px';
		}
	}

	// note: this empties out innerText
	var shadow = Compat.createShadowRoot(this.node);
	shadow.applyAuthorStyles = false;
	shadow.resetStyleInheritance = false;
	shadow.appendChild(this.delegate);
};
Widgets.adapters.ContentEditable.prototype = Object.create(Widgets.Styled.prototype);
Widgets.adapters.ContentEditable.prototype.constructor = Widgets.adapters.ContentEditable;

Widgets.adapters.ContentEditable.stopEvent = function (e) {
	e.stopPropagation();
};

Widgets.adapters.ContentEditable.prototype.onFocus = function (e) {
	this.delegate.focus();
};

Widgets.adapters.ContentEditable.prototype.onInput = function (e) {
	this.node.textContent = Codec.encode(Crypto.defaultSuffix, this.delegate.value);
};

Widgets.adapters.ContentEditable.prototype.updateContent = function () {
	// caveat: this is stuck with the less nice textContent because innerText sees the composed DOM
	this.delegate.value = Rewriter.processString(this.node.textContent);
};

Widgets.adapters.IFrame = function (e) {
	Widgets.AbstractAdapter.call(this, e);
	e.addEventListener('load', this.onLoad.bind(this));
	this.onLoad(null);
};
Widgets.adapters.IFrame.prototype = Object.create(Widgets.AbstractAdapter.prototype);
Widgets.adapters.IFrame.prototype.constructor = Widgets.adapters.IFrame;

Widgets.adapters.IFrame.prototype.onLoad = function () {
	try {
		// test access first
		this.node.contentDocument;
		Content.propagate(this.node);
		Widgets.init(this.node.contentWindow);
		Observer.init(this.node.contentDocument);
	} catch (e) {
		// console.warn(e); // %%%
	}
};

Widgets.init = function (win) {
	// caveat: capture listeners registered before this will not see updated value
	win.addEventListener('input', Widgets.onInputEarly, true);
};

Widgets.onInputEarly = function (e) {
	if ('zerokitInputEarly' in e.target) {
		e.target.zerokitInputEarly();
	}
};

Widgets.createAdapter = function (node) {
	var tag = node.tagName.toLowerCase();
	if (tag === 'form') {
		return new Widgets.adapters.Form(node);
	} else if (tag === 'input') {
		if (node.type === 'text') {
			// TODO: more heuristics
			return new Widgets.adapters.Input(node);
		}
	} else if (tag === 'textarea') {
		return new Widgets.adapters.TextArea(node);
	} else if (tag === 'iframe') {
		return new Widgets.adapters.IFrame(node);
	} else {
		if (node.contentEditable === 'true') {
			return new Widgets.adapters.ContentEditable(node);
		}
	}
	return null;
};

Widgets.updateContent = function (node) {
	if (!node) return;
	if (node.nodeType === Document.ELEMENT_NODE) {
		if ('zerokitUpdateContent' in node) {
			node.zerokitUpdateContent();
			return;
		}
	}
	Widgets.updateContent(node.parentNode);
};

Widgets.onAdd = function (node) {
	if ('zerokitShimmed' in node) {
		// no need!
	} else {
		if (Widgets.createAdapter(node)) {
			node.zerokitShimmed = true;
		}
	}
};

var Observer = {
	OPTIONS: {
		childList: true,
		characterData: true,
		subtree: true
	},
	observer: null
};

Observer.onCharacterData = function (target) {
	// console.log('characterData', target, target.nodeValue); // %%%
	Widgets.updateContent(target);
};

Observer.onChildList = function (target) {
	Widgets.updateContent(target);
};

Observer.onAddedNode = function (impl, target, addedNode) {
	// console.log('addedNode', target, addedNode); // %%%
	if (addedNode.nodeType === Document.ELEMENT_NODE) {
		var widgets = addedNode.querySelectorAll(Widgets.WIDGET_SELECTOR);
		for (var i = 0; i < widgets.length; i++) {
			Widgets.onAdd(widgets[i]);
		}
		Widgets.onAdd(addedNode);
	}
	Rewriter.rewriteMarkup(impl, addedNode);
};

Observer.callback = function (mutationRecords, observer) {
	for (var i = 0; i < mutationRecords.length; i++) {
		var mutationRecord = mutationRecords[i];
		var target = mutationRecord.target;
		var impl = target.ownerDocument;
		switch (mutationRecord.type) {
		case 'characterData':
			if (!target.ownerDocument.contains(target)) continue;
			Observer.onCharacterData(target);
			break;
		case 'childList':
			Observer.onChildList(target);
			var addedNodes = mutationRecord.addedNodes;
			for (var j = 0; j < addedNodes.length; j++) {
				var addedNode = addedNodes[j];
				if (!addedNode.ownerDocument.contains(addedNode)) continue;
				Observer.onAddedNode(impl, target, addedNode);
			}
			break;
		}
	}
};

Observer.init = function (doc) {
	if (doc.head) Observer.onAddedNode(doc, doc.documentElement, doc.head);
	if (doc.body) Observer.onAddedNode(doc, doc.documentElement, doc.body);
	Observer.observer = new MutationObserver(Observer.callback);
	Observer.observer.observe(doc.documentElement, Observer.OPTIONS);
};

var Startup = {
	key: null
};

Startup.init = function () {
	Startup.key = 'origin-' + window.location.origin;
	chrome.storage.sync.get(Startup.key, Startup.onGet);
};

Startup.onGet = function (items) {
	if (!(Startup.key in items)) throw new Error('origin not configured');
	var site = items[Startup.key];
	Crypto.keys = site.keys;
	Crypto.defaultSuffix = site.defaultSuffix;

	Content.init();
	Widgets.init(window);
	Observer.init(document);
};

Startup.init();
