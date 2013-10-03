(function () {

// this is from from http://crypto.stanford.edu/sjcl/sjcl.js
// narrowed down to bitArray, base64, utf8String, aes, and ccm
var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};"undefined"!=typeof module&&module.exports&&(module.exports=sjcl);sjcl.bitArray={bitSlice:function(a,b,c){a=sjcl.bitArray._shiftRight(a.slice(b/32),32-(b&31)).slice(1);return void 0===c?a:sjcl.bitArray.clamp(a,c-b)},extract:function(a,b,c){var e=Math.floor(-b-c&31);return((b+c-1^b)&-32?a[b/32|0]<<32-e^a[b/32+1|0]>>>e:a[b/32|0]>>>e)&(1<<c)-1},concat:function(a,b){if(0===a.length||0===b.length)return a.concat(b);var c=a[a.length-1],e=sjcl.bitArray.getPartial(c);return 32===e?a.concat(b):sjcl.bitArray._shiftRight(b,e,c|0,a.slice(0,a.length-1))},bitLength:function(a){var b=a.length;return 0===b?0:32*(b-1)+sjcl.bitArray.getPartial(a[b-1])},clamp:function(a,b){if(32*a.length<b)return a;a=a.slice(0,Math.ceil(b/32));var c=a.length;b&=31;0<c&&b&&(a[c-1]=sjcl.bitArray.partial(b,a[c-1]&2147483648>>b-1,1));return a},partial:function(a,b,c){return 32===a?b:(c?b|0:b<<32-a)+1099511627776*a},getPartial:function(a){return Math.round(a/1099511627776)||32},equal:function(a,b){if(sjcl.bitArray.bitLength(a)!==sjcl.bitArray.bitLength(b))return!1;var c=0,e;for(e=0;e<a.length;e++)c|=a[e]^b[e];return 0===c},_shiftRight:function(a,b,c,e){var d;d=0;for(void 0===e&&(e=[]);32<=b;b-=32)e.push(c),c=0;if(0===b)return e.concat(a);for(d=0;d<a.length;d++)e.push(c|a[d]>>>b),c=a[d]<<32-b;d=a.length?a[a.length-1]:0;a=sjcl.bitArray.getPartial(d);e.push(sjcl.bitArray.partial(b+a&31,32<b+a?c:e.pop(),1));return e},_xor4:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};sjcl.codec.base64={_chars:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",fromBits:function(a,b,c){var e="",d=0,f=sjcl.codec.base64._chars,g=0,h=sjcl.bitArray.bitLength(a);c&&(f=f.substr(0,62)+"-_");for(c=0;6*e.length<h;)e+=f.charAt((g^a[c]>>>d)>>>26),6>d?(g=a[c]<<6-d,d+=26,c++):(g<<=6,d-=6);for(;e.length&3&&!b;)e+="=";return e},toBits:function(a,b){a=a.replace(/\s|=/g,"");var c=[],e,d=0,f=sjcl.codec.base64._chars,g=0,h;b&&(f=f.substr(0,62)+"-_");for(e=0;e<a.length;e++){h=f.indexOf(a.charAt(e));if(0>h)throw new sjcl.exception.invalid("this isn't base64!");26<d?(d-=26,c.push(g^h>>>d),g=h<<32-d):(d+=6,g^=h<<32-d)}d&56&&c.push(sjcl.bitArray.partial(d&56,g,1));return c}};sjcl.codec.base64url={fromBits:function(a){return sjcl.codec.base64.fromBits(a,1,1)},toBits:function(a){return sjcl.codec.base64.toBits(a,1)}};sjcl.codec.utf8String={fromBits:function(a){var b="",c=sjcl.bitArray.bitLength(a),e,d;for(e=0;e<c/8;e++)0===(e&3)&&(d=a[e/4]),b+=String.fromCharCode(d>>>24),d<<=8;return decodeURIComponent(escape(b))},toBits:function(a){a=unescape(encodeURIComponent(a));var b=[],c,e=0;for(c=0;c<a.length;c++)e=e<<8|a.charCodeAt(c),3===(c&3)&&(b.push(e),e=0);c&3&&b.push(sjcl.bitArray.partial(8*(c&3),e));return b}};sjcl.cipher.aes=function(a){this._tables[0][0][0]||this._precompute();var b,c,e,d,f=this._tables[0][4],g=this._tables[1];b=a.length;var h=1;if(4!==b&&6!==b&&8!==b)throw new sjcl.exception.invalid("invalid aes key size");this._key=[e=a.slice(0),d=[]];for(a=b;a<4*b+28;a++){c=e[a-1];if(0===a%b||8===b&&4===a%b)c=f[c>>>24]<<24^f[c>>16&255]<<16^f[c>>8&255]<<8^f[c&255],0===a%b&&(c=c<<8^c>>>24^h<<24,h=h<<1^283*(h>>7));e[a]=e[a-b]^c}for(b=0;a;b++,a--)c=e[b&3?a:a-4],d[b]=4>=a||4>b?c:g[0][f[c>>>24]]^g[1][f[c>>16&255]]^g[2][f[c>>8&255]]^g[3][f[c&255]]};sjcl.cipher.aes.prototype={encrypt:function(a){return this._crypt(a,0)},decrypt:function(a){return this._crypt(a,1)},_tables:[[[],[],[],[],[]],[[],[],[],[],[]]],_precompute:function(){var a=this._tables[0],b=this._tables[1],c=a[4],e=b[4],d,f,g,h=[],k=[],m,p,l,n;for(d=0;256>d;d++)k[(h[d]=d<<1^283*(d>>7))^d]=d;for(f=g=0;!c[f];f^=m||1,g=k[g]||1)for(l=g^g<<1^g<<2^g<<3^g<<4,l=l>>8^l&255^99,c[f]=l,e[l]=f,p=h[d=h[m=h[f]]],n=16843009*p^65537*d^257*m^16843008*f,p=257*h[l]^16843008*l,d=0;4>d;d++)a[d][f]=p=p<<24^p>>>8,b[d][l]=n=n<<24^n>>>8;for(d=0;5>d;d++)a[d]=a[d].slice(0),b[d]=b[d].slice(0)},_crypt:function(a,b){if(4!==a.length)throw new sjcl.exception.invalid("invalid aes block size");var c=this._key[b],e=a[0]^c[0],d=a[b?3:1]^c[1],f=a[2]^c[2],g=a[b?1:3]^c[3],h,k,m,p=c.length/4-2,l,n=4,v=[0,0,0,0];h=this._tables[b];var q=h[0],r=h[1],s=h[2],t=h[3],u=h[4];for(l=0;l<p;l++)h=q[e>>>24]^r[d>>16&255]^s[f>>8&255]^t[g&255]^c[n],k=q[d>>>24]^r[f>>16&255]^s[g>>8&255]^t[e&255]^c[n+1],m=q[f>>>24]^r[g>>16&255]^s[e>>8&255]^t[d&255]^c[n+2],g=q[g>>>24]^r[e>>16&255]^s[d>>8&255]^t[f&255]^c[n+3],n+=4,e=h,d=k,f=m;for(l=0;4>l;l++)v[b?3&-l:l]=u[e>>>24]<<24^u[d>>16&255]<<16^u[f>>8&255]<<8^u[g&255]^c[n++],h=e,e=d,d=f,f=g,g=h;return v}};sjcl.mode.ccm={name:"ccm",encrypt:function(a,b,c,e,d){var f,g=b.slice(0),h=sjcl.bitArray,k=h.bitLength(c)/8,m=h.bitLength(g)/8;d=d||64;e=e||[];if(7>k)throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");for(f=2;4>f&&m>>>8*f;f++);f<15-k&&(f=15-k);c=h.clamp(c,8*(15-f));b=sjcl.mode.ccm._computeTag(a,b,c,e,d,f);g=sjcl.mode.ccm._ctrMode(a,g,c,b,d,f);return h.concat(g.data,g.tag)},decrypt:function(a,b,c,e,d){d=d||64;e=e||[];var f=sjcl.bitArray,g=f.bitLength(c)/8,h=f.bitLength(b),k=f.clamp(b,h-d),m=f.bitSlice(b,h-d),h=(h-d)/8;if(7>g)throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");for(b=2;4>b&&h>>>8*b;b++);b<15-g&&(b=15-g);c=f.clamp(c,8*(15-b));k=sjcl.mode.ccm._ctrMode(a,k,c,m,d,b);a=sjcl.mode.ccm._computeTag(a,k.data,c,e,d,b);if(!f.equal(k.tag,a))throw new sjcl.exception.corrupt("ccm: tag doesn't match");return k.data},_computeTag:function(a,b,c,e,d,f){var g=[],h=sjcl.bitArray,k=h._xor4;d/=8;if(d%2||4>d||16<d)throw new sjcl.exception.invalid("ccm: invalid tag length");if(4294967295<e.length||4294967295<b.length)throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data");f=[h.partial(8,(e.length?64:0)|d-2<<2|f-1)];f=h.concat(f,c);f[3]|=h.bitLength(b)/8;f=a.encrypt(f);if(e.length)for(c=h.bitLength(e)/8,65279>=c?g=[h.partial(16,c)]:4294967295>=c&&(g=h.concat([h.partial(16,65534)],[c])),g=h.concat(g,e),e=0;e<g.length;e+=4)f=a.encrypt(k(f,g.slice(e,e+4).concat([0,0,0])));for(e=0;e<b.length;e+=4)f=a.encrypt(k(f,b.slice(e,e+4).concat([0,0,0])));return h.clamp(f,8*d)},_ctrMode:function(a,b,c,e,d,f){var g,h=sjcl.bitArray;g=h._xor4;var k=b.length,m=h.bitLength(b);c=h.concat([h.partial(8,f-1)],c).concat([0,0,0]).slice(0,4);e=h.bitSlice(g(e,a.encrypt(c)),0,d);if(!k)return{tag:e,data:[]};for(g=0;g<k;g+=4)c[3]++,d=a.encrypt(c),b[g]^=d[0],b[g+1]^=d[1],b[g+2]^=d[2],b[g+3]^=d[3];return{tag:e,data:h.clamp(b,m)}}};

var Crypto = {
	keys: {},
	defaultSuffix: '',
	cipher: sjcl.cipher.aes,
	mode: sjcl.mode.ccm
};

Crypto.keys[''] = [0x2d882231, 0x346dfd19, 0x6ed33f4f, 0x4751d2d5];

Crypto.getKey = function (suffix) {
	if (!(suffix in Crypto.keys)) throw new Error('unknown suffix', suffix);
	return Crypto.keys[suffix];
};

Crypto.encrypt = function (key, data, adata) {
	var pt = sjcl.codec.utf8String.toBits(data);
	var iv = Array.prototype.slice.call(window.crypto.getRandomValues(new Uint32Array(4)));
	var ct = Crypto.mode.encrypt(new Crypto.cipher(key), pt, iv, sjcl.codec.utf8String.toBits(adata));
	return sjcl.codec.base64.fromBits(iv.concat(ct));
};

Crypto.decrypt = function (key, data, adata) {
	var ct = sjcl.codec.base64.toBits(data);
	var iv = ct.splice(0, 4);
	var pt = Crypto.mode.decrypt(new Crypto.cipher(key), ct, iv, sjcl.codec.utf8String.toBits(adata));
	return sjcl.codec.utf8String.fromBits(pt);
};

// Polymer's ShadowDOM polyfill doesn't support document.createNodeIterator
// this implements something like document.createNodeIterator(root, NodeFilter.SHOW_TEXT)
// no need for liveness
// might as well skip empty text nodes too
var SnapshotTextIterator = function (root) {
	this.index = 0;
	this.nodes = [];
	this.walk(root);
};

SnapshotTextIterator.prototype.walk = function (node) {
	if (node.nodeType === document.TEXT_NODE) {
		if (node.data.length == 0) return;
		this.nodes.push(node);
	} else if (node.nodeType === document.ELEMENT_NODE) {
		for (var i = 0; i < node.childNodes.length; i++) {
			this.walk(node.childNodes[i]);
		}
	}
};

SnapshotTextIterator.prototype.nextNode = function (node) {
	return this.nodes[this.index++];
};

var Scanner = function (root) {
	this.root = root;
	this.iter = new SnapshotTextIterator(root);
	this.u = 0;
	this.v = 0;
	this.next();
};

Scanner.getNodeLength = function (node) {
	// simplified implementation of
	// http://dom.spec.whatwg.org/#concept-node-length
	// supporting only Element and CharacterData Nodes
	if (node.nodeType === document.TYPE_ELEMENT) {
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

Scanner.prototype.sink = function (range) {
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

	// 3. sink from common ancestor to first ancestor with sibling
	while (ancestor !== this.root) {
		if (ancestor.previousSibling) break;
		if (ancestor.nextSibling) break;
		ancestor = ancestor.parentNode;
	}

	// 4. done
	range.selectNode(ancestor);
};

var Tags = {
	TAG_TEST_PATTERN: /^[@#]\w+$/,
	TAG_PATTERN: /[@#]\w+/g
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

Tags.readTags = function (scanner, text, match) {
	var start = match.index + 9 + match[1].length + 1;
	var end = start + match[2].length;
	var tags = [];
	while (start < end) {
		var comma = text.indexOf(',', start);
		if (comma === -1 || comma > end) comma = end;
		var tag = text.slice(start, comma);
		if (!Tags.TAG_TEST_PATTERN.test(tag)) continue;
		var range = document.createRange();
		scanner.setStart(range, start);
		scanner.setEnd(range, comma);
		scanner.sink(range);
		tags.push([tag, range.cloneContents()]);
		start = comma + 1;
	}
	return tags;
};

Tags.insertTags = function (message, tags) {
	if (!tags.length) return document.createTextNode(message);
	var frags = [];
	var map = {};
	for (var i = 0; i < tags.length; i++) {
		frags.push(tags[i][0] + '\\b');
		map[tags[i][0]] = tags[i][1];
	}
	var pattern = new RegExp(frags.join('|'), 'g');
	var result = document.createDocumentFragment();
	var last = 0;
	var match;
	while (match = pattern.exec(message)) {
		if (match.index > last) {
			result.appendChild(document.createTextNode(message.slice(last, match.index)));
		}
		result.appendChild(map[match[0]].cloneNode(true)); // lol chrome defaults to (false)
		last = match.index + match[0].length;
	}
	if (last < message.length) {
		result.appendChild(document.createTextNode(message.slice(last)));
	}
	return result;
};

var Codec = {
	CODE_PATTERN: /=\?zerokit(\w*)\?([\w@#,]*)\?([A-Za-z0-9+\/=]*)\?=/g
};

Codec.encode = function (suffix, message) {
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

Rewriter.findCodes = function (node) {
	// since it's textContent, things get weird with comments and processing instructions
	var text = node.textContent;
	if (Rewriter.fastFail(text)) return null;
	var codes = [];
	var scanner = new Scanner(node);
	var match;
	while (match = Codec.CODE_PATTERN.exec(text)) {
		try {
			var messageText = Codec.decode(match[1], match[2], match[3]);
			var range = document.createRange();
			scanner.setStart(range, match.index);
			var messageNode;
			if (match[2]) {
				var tags = Tags.readTags(scanner, text, match);
				messageNode = Tags.insertTags(messageText, tags);
			} else {
				messageNode = document.createTextNode(messageText);
			}
			scanner.setEnd(range, match.index + match[0].length);
			if (range.startContainer.parentNode !== range.endContainer.parentNode) throw new Error('aborting suspicious range', range.startContainer.parentNode, range.endContainer.parentNode);
			codes.push([range, messageNode]);
		} catch (e) {
			console.warn(e);
		}
	}
	return codes;
};

Rewriter.repaceCodes = function (codes) {
	for (var i = 0; i < codes.length; i++) {
		var range = codes[i][0];
		var messageNode = codes[i][1];
		var span = document.createElement('span');
		span.dataset.zerokitReplaced = 'yes';
		range.surroundContents(span);
		var shadow = span.createShadowRoot();
		shadow.appendChild(messageNode);
	}
};

Rewriter.rewriteMarkup = function (node) {
	var codes = Rewriter.findCodes(node);
	if (codes) Rewriter.repaceCodes(codes);
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
	WIDGET_SELECTOR: 'input,textarea,[contenteditable]',
	DELEGATED_SELECTOR: '[data-zerokit-shimmed]',
	PROPS: {
		inputValue: Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value'),
		textareaValue: Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value'),
		innerHTML: Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML'),
		textContent: Object.getOwnPropertyDescriptor(Node.prototype, 'textContent')
	},
	adapters: {}
};

Widgets.adapters.input = {
	name: 'input',
	init: function (e) {
		e.value = Rewriter.processString(e.value);
	},
	props: {
		value: {
			get: function () {
				var orig = Widgets.PROPS.inputValue.get.call(this);
				return Codec.encode(Crypto.defaultSuffix, orig);
			},
			set: function (v) {
				var clear = Rewriter.processString(v);
				Widgets.PROPS.inputValue.set.call(this, v);
			}
		}
	}
};

Widgets.adapters.textarea = {
	name: 'textarea',
	init: function (e) {
		e.value = Rewriter.processString(e.value);
	},
	props: {
		value: {
			get: function () {
				var orig = Widgets.PROPS.textareaValue.get.call(this);
				return Codec.encode(Crypto.defaultSuffix, orig);
			},
			set: function (v) {
				var clear = Rewriter.processString(v);
				Widgets.PROPS.textareaValue.set.call(this, v);
			}
		}
	}
};

Widgets.adapters.contentEditable = {
	name: 'contentEditable',
	init: function (e) {
		// observer/rewriter should take care of it
	},
	props: {
		innerHTML: {
			get: function () {
				var orig = Widgets.PROPS.textContent.get.call(this);
				// result of encode is HTML safe
				return Codec.encode(Crypto.defaultSuffix, orig);
			},
			// observer/rewriter should take care of it
			set: Widgets.PROPS.innerHTML.set
		}
	}
};

Widgets.init = function () {
	var ss = document.createElement('style');
	ss.textContent =
		Widgets.DELEGATED_SELECTOR + '{outline:1px solid #c00040!important;outline-offset:-1px!important;}' +
		Widgets.DELEGATED_SELECTOR + ':focus{outline:2px solid #ff0055!important;}';
	document.head.appendChild(ss);
};

Widgets.getAdapter = function (node) {
	var tag = node.tagName.toLowerCase();
	if (tag === 'input') {
		if (node.type === 'text') {
			// TODO: more heuristics
			return Widgets.adapters.input;
		}
	} else if (tag === 'textarea') {
		return Widgets.adapters.textarea;
	} else {
		if (node.contentEditable === 'true') {
			return Widgets.adapters.contentEditable;
		}
	}
	return null;
};

Widgets.shim = function (node) {
	var adapter = Widgets.getAdapter(node);
	if (!adapter) return;

	if ('zerokitShimmed' in node.dataset) return;
	node.dataset.zerokitShimmed = adapter.name;

	adapter.init(node);
	Object.defineProperties(node, adapter.props);
};

Widgets.unshim = function (node) {
	if (!('zerokitShimmed' in node.dataset)) return;
	var adapterName = node.dataset.zerokitShimmed;
	delete node.dataset.zerokitShimmed;

	if (!Widgets.adapters.hasOwnProperty(adapterName)) return;
	var adapter = Widgets.adapters[adapterName];

	for (var prop in adapter.props) {
		delete node[prop];
	}
};

var Observer = {
	OPTIONS: {
		childList: true,
		// characterData: true, // maybe not needed?
		subtree: true
	},
	observer: null
};

Observer.on = function () {
	Observer.observer.observe(document.body, Observer.OPTIONS);
};

Observer.off = function () {
	Observer.observer.disconnect();
};

// Observer.onCharacterData = function (target) {
	// console.log('characterData', target, target.nodeValue); // %%%
// };

Observer.onAddedNode = function (target, addedNode) {
	// console.log('addedNode', target, addedNode); // %%%
	Rewriter.rewriteMarkup(addedNode);
	if (addedNode.nodeType !== document.ELEMENT_NODE) return;
	var widgets = addedNode.querySelectorAll(Widgets.WIDGET_SELECTOR);
	for (var i = 0; i < widgets.length; i++) {
		Widgets.shim(widgets[i]);
	}
	Widgets.shim(addedNode);
};

Observer.onRemovedNode = function (target, removedNode) {
	// console.log('removedNode', target, removedNode); // %%%
	if (removedNode.nodeType !== document.ELEMENT_NODE) return;
	var delegated = removedNode.querySelectorAll(Widgets.DELEGATED_SELECTOR);
	for (var i = 0; i < delegated.length; i++) {
		Widgets.unshim(delegated[i]);
	}
	Widgets.unshim(removedNode);
}

Observer.callback = function (mutationRecords) {
	Observer.off();
	for (var i = 0; i < mutationRecords.length; i++) {
		var mutationRecord = mutationRecords[i];
		switch (mutationRecord.type) {
		// case 'characterData':
			// Observer.onCharacterData(mutationRecord.target);
			// break;
		case 'childList':
			for (var j = 0; j < mutationRecord.removedNodes.length; j++) {
				Observer.onRemovedNode(mutationRecord.target, mutationRecord.removedNodes[j]);
			}
			for (j = 0; j < mutationRecord.addedNodes.length; j++) {
				Observer.onAddedNode(mutationRecord.target, mutationRecord.addedNodes[j]);
			}
			break;
		}
	}
	Observer.on();
};

Observer.init = function () {
	if (!document.body) {
		document.addEventListener('DOMContentLoaded', Observer.init);
		return;
	}
	Observer.onAddedNode(document.documentElement, document.body);
	Observer.observer = new MutationObserver(Observer.callback);
	Observer.on();
};

Widgets.init();
Observer.init();

}());
