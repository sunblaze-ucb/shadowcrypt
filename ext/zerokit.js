var Compat = {
	createShadowRoot: function (e) { return e.webkitCreateShadowRoot(); },
	deleteShadowRootProp: function (e) { Content.deleteProp(e, 'webkitShadowRoot'); },
	afterSubmit: function (f) { setTimeout(f, 0); },
	getInnerText: function (e) { return e.innerText; },
	matches: function (e, s) { return e.webkitMatchesSelector(s); },
	transform: '-webkit-transform',
	transformProp: 'WebkitTransform',
	transformOrigin: '-webkit-transform-origin'
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

	function onDeleteProp(e) {
		var node = e.target;
		var name = e.detail.name;
		delete node[name];
	}

	function notInContentEditable(win, selection) {
		return !(win.document.hasFocus() && win.document.activeElement.contentEditable === 'true');
	}

	var warned = false;

	function gateMethodProto(proto, methodName, predicate) {
		var orig = proto[methodName];
		proto[methodName] = function () {
			if (predicate(this)) return orig.apply(this, arguments);
			if (!warned) {
				console.warn('ignoring method ' + methodName);
				warned = true;
			}
		};
	}

	function setup(win) {
		win.addEventListener('zerokit-add-listeners', onSetup, true);
		win.addEventListener('zerokit-shim-prop', onShimProp, true);
		win.addEventListener('zerokit-shim-method', onShimMethod, true);
		win.addEventListener('zerokit-delete-prop', onDeleteProp, true);
		// caveat: you can't touch selection anymore
		gateMethodProto(win.Selection.prototype, 'removeAllRanges', notInContentEditable.bind(null, win));
		gateMethodProto(win.Selection.prototype, 'addRange', notInContentEditable.bind(null, win));
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

Content.deleteProp = function (node, name) {
	var event = new CustomEvent('zerokit-delete-prop', {detail: {name: name}});
	node.dispatchEvent(event);
};

// this is sjcl configured with:
// --compress=yui --without-all --with-aes --with-bitArray --with-codecString --with-codecHex --with-codecBase64 --with-sha256 --with-ccm --with-hmac
var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};sjcl.cipher.aes=function(h){if(!this._tables[0][0][0]){this._precompute()}var d,c,e,g,l,f=this._tables[0][4],k=this._tables[1],a=h.length,b=1;if(a!==4&&a!==6&&a!==8){throw new sjcl.exception.invalid("invalid aes key size")}this._key=[g=h.slice(0),l=[]];for(d=a;d<4*a+28;d++){e=g[d-1];if(d%a===0||(a===8&&d%a===4)){e=f[e>>>24]<<24^f[e>>16&255]<<16^f[e>>8&255]<<8^f[e&255];if(d%a===0){e=e<<8^e>>>24^b<<24;b=b<<1^(b>>7)*283}}g[d]=g[d-a]^e}for(c=0;d;c++,d--){e=g[c&3?d:d-4];if(d<=4||c<4){l[c]=e}else{l[c]=k[0][f[e>>>24]]^k[1][f[e>>16&255]]^k[2][f[e>>8&255]]^k[3][f[e&255]]}}};sjcl.cipher.aes.prototype={encrypt:function(a){return this._crypt(a,0)},decrypt:function(a){return this._crypt(a,1)},_tables:[[[],[],[],[],[]],[[],[],[],[],[]]],_precompute:function(){var j=this._tables[0],q=this._tables[1],h=j[4],n=q[4],g,l,f,k=[],c=[],b,p,m,o,e,a;for(g=0;g<0x100;g++){c[(k[g]=g<<1^(g>>7)*283)^g]=g}for(l=f=0;!h[l];l^=b||1,f=c[f]||1){o=f^f<<1^f<<2^f<<3^f<<4;o=o>>8^o&255^99;h[l]=o;n[o]=l;m=k[p=k[b=k[l]]];a=m*0x1010101^p*0x10001^b*0x101^l*0x1010100;e=k[o]*0x101^o*0x1010100;for(g=0;g<4;g++){j[g][l]=e=e<<24^e>>>8;q[g][o]=a=a<<24^a>>>8}}for(g=0;g<5;g++){j[g]=j[g].slice(0);q[g]=q[g].slice(0)}},_crypt:function(k,n){if(k.length!==4){throw new sjcl.exception.invalid("invalid aes block size")}var y=this._key[n],v=k[0]^y[0],u=k[n?3:1]^y[1],t=k[2]^y[2],s=k[n?1:3]^y[3],w,e,m,x=y.length/4-2,p,o=4,q=[0,0,0,0],r=this._tables[n],j=r[0],h=r[1],g=r[2],f=r[3],l=r[4];for(p=0;p<x;p++){w=j[v>>>24]^h[u>>16&255]^g[t>>8&255]^f[s&255]^y[o];e=j[u>>>24]^h[t>>16&255]^g[s>>8&255]^f[v&255]^y[o+1];m=j[t>>>24]^h[s>>16&255]^g[v>>8&255]^f[u&255]^y[o+2];s=j[s>>>24]^h[v>>16&255]^g[u>>8&255]^f[t&255]^y[o+3];o+=4;v=w;u=e;t=m}for(p=0;p<4;p++){q[n?3&-p:p]=l[v>>>24]<<24^l[u>>16&255]<<16^l[t>>8&255]<<8^l[s&255]^y[o++];w=v;v=u;u=t;t=s;s=w}return q}};sjcl.bitArray={bitSlice:function(b,c,d){b=sjcl.bitArray._shiftRight(b.slice(c/32),32-(c&31)).slice(1);return(d===undefined)?b:sjcl.bitArray.clamp(b,d-c)},extract:function(c,d,f){var b,e=Math.floor((-d-f)&31);if((d+f-1^d)&-32){b=(c[d/32|0]<<(32-e))^(c[d/32+1|0]>>>e)}else{b=c[d/32|0]>>>e}return b&((1<<f)-1)},concat:function(c,a){if(c.length===0||a.length===0){return c.concat(a)}var d,e,f=c[c.length-1],b=sjcl.bitArray.getPartial(f);if(b===32){return c.concat(a)}else{return sjcl.bitArray._shiftRight(a,b,f|0,c.slice(0,c.length-1))}},bitLength:function(d){var c=d.length,b;if(c===0){return 0}b=d[c-1];return(c-1)*32+sjcl.bitArray.getPartial(b)},clamp:function(d,b){if(d.length*32<b){return d}d=d.slice(0,Math.ceil(b/32));var c=d.length;b=b&31;if(c>0&&b){d[c-1]=sjcl.bitArray.partial(b,d[c-1]&2147483648>>(b-1),1)}return d},partial:function(b,a,c){if(b===32){return a}return(c?a|0:a<<(32-b))+b*0x10000000000},getPartial:function(a){return Math.round(a/0x10000000000)||32},equal:function(e,d){if(sjcl.bitArray.bitLength(e)!==sjcl.bitArray.bitLength(d)){return false}var c=0,f;for(f=0;f<e.length;f++){c|=e[f]^d[f]}return(c===0)},_shiftRight:function(d,c,h,f){var g,b=0,e;if(f===undefined){f=[]}for(;c>=32;c-=32){f.push(h);h=0}if(c===0){return f.concat(d)}for(g=0;g<d.length;g++){f.push(h|d[g]>>>c);h=d[g]<<(32-c)}b=d.length?d[d.length-1]:0;e=sjcl.bitArray.getPartial(b);f.push(sjcl.bitArray.partial(c+e&31,(c+e>32)?h:f.pop(),1));return f},_xor4:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};sjcl.codec.utf8String={fromBits:function(a){var b="",e=sjcl.bitArray.bitLength(a),d,c;for(d=0;d<e/8;d++){if((d&3)===0){c=a[d/4]}b+=String.fromCharCode(c>>>24);c<<=8}return decodeURIComponent(escape(b))},toBits:function(d){d=unescape(encodeURIComponent(d));var a=[],c,b=0;for(c=0;c<d.length;c++){b=b<<8|d.charCodeAt(c);if((c&3)===3){a.push(b);b=0}}if(c&3){a.push(sjcl.bitArray.partial(8*(c&3),b))}return a}};sjcl.codec.hex={fromBits:function(b){var c="",d,a;for(d=0;d<b.length;d++){c+=((b[d]|0)+0xf00000000000).toString(16).substr(4)}return c.substr(0,sjcl.bitArray.bitLength(b)/4)},toBits:function(d){var c,b=[],a;d=d.replace(/\s|0x/g,"");a=d.length;d=d+"00000000";for(c=0;c<d.length;c+=8){b.push(parseInt(d.substr(c,8),16)^0)}return sjcl.bitArray.clamp(b,a*4)}};sjcl.codec.base64={_chars:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",fromBits:function(g,k,b){var d="",e,j=0,h=sjcl.codec.base64._chars,f=0,a=sjcl.bitArray.bitLength(g);if(b){h=h.substr(0,62)+"-_"}for(e=0;d.length*6<a;){d+=h.charAt((f^g[e]>>>j)>>>26);if(j<6){f=g[e]<<(6-j);j+=26;e++}else{f<<=6;j-=6}}while((d.length&3)&&!k){d+="="}return d},toBits:function(h,f){h=h.replace(/\s|=/g,"");var d=[],e,g=0,j=sjcl.codec.base64._chars,b=0,a;if(f){j=j.substr(0,62)+"-_"}for(e=0;e<h.length;e++){a=j.indexOf(h.charAt(e));if(a<0){throw new sjcl.exception.invalid("this isn't base64!")}if(g>26){g-=26;d.push(b^a>>>g);b=a<<(32-g)}else{g+=6;b^=a<<(32-g)}}if(g&56){d.push(sjcl.bitArray.partial(g&56,b,1))}return d}};sjcl.codec.base64url={fromBits:function(a){return sjcl.codec.base64.fromBits(a,1,1)},toBits:function(a){return sjcl.codec.base64.toBits(a,1)}};sjcl.hash.sha256=function(a){if(!this._key[0]){this._precompute()}if(a){this._h=a._h.slice(0);this._buffer=a._buffer.slice(0);this._length=a._length}else{this.reset()}};sjcl.hash.sha256.hash=function(a){return(new sjcl.hash.sha256()).update(a).finalize()};sjcl.hash.sha256.prototype={blockSize:512,reset:function(){this._h=this._init.slice(0);this._buffer=[];this._length=0;return this},update:function(f){if(typeof f==="string"){f=sjcl.codec.utf8String.toBits(f)}var e,a=this._buffer=sjcl.bitArray.concat(this._buffer,f),d=this._length,c=this._length=d+sjcl.bitArray.bitLength(f);for(e=512+d&-512;e<=c;e+=512){this._block(a.splice(0,16))}return this},finalize:function(){var c,a=this._buffer,d=this._h;a=sjcl.bitArray.concat(a,[sjcl.bitArray.partial(1,1)]);for(c=a.length+2;c&15;c++){a.push(0)}a.push(Math.floor(this._length/0x100000000));a.push(this._length|0);while(a.length){this._block(a.splice(0,16))}this.reset();return d},_init:[],_key:[],_precompute:function(){var d=0,c=2,b;function a(e){return(e-Math.floor(e))*0x100000000|0}outer:for(;d<64;c++){for(b=2;b*b<=c;b++){if(c%b===0){continue outer}}if(d<8){this._init[d]=a(Math.pow(c,1/2))}this._key[d]=a(Math.pow(c,1/3));d++}},_block:function(q){var e,f,t,s,u=q.slice(0),j=this._h,c=this._key,r=j[0],p=j[1],o=j[2],n=j[3],m=j[4],l=j[5],g=j[6],d=j[7];for(e=0;e<64;e++){if(e<16){f=u[e]}else{t=u[(e+1)&15];s=u[(e+14)&15];f=u[e&15]=((t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(s>>>17^s>>>19^s>>>10^s<<15^s<<13)+u[e&15]+u[(e+9)&15])|0}f=(f+d+(m>>>6^m>>>11^m>>>25^m<<26^m<<21^m<<7)+(g^m&(l^g))+c[e]);d=g;g=l;l=m;m=n+f|0;n=o;o=p;p=r;r=(f+((p&o)^(n&(p^o)))+(p>>>2^p>>>13^p>>>22^p<<30^p<<19^p<<10))|0}j[0]=j[0]+r|0;j[1]=j[1]+p|0;j[2]=j[2]+o|0;j[3]=j[3]+n|0;j[4]=j[4]+m|0;j[5]=j[5]+l|0;j[6]=j[6]+g|0;j[7]=j[7]+d|0}};sjcl.mode.ccm={name:"ccm",encrypt:function(c,b,e,m,d){var j,g,f=b.slice(0),l,k=sjcl.bitArray,a=k.bitLength(e)/8,h=k.bitLength(f)/8;d=d||64;m=m||[];if(a<7){throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes")}for(j=2;j<4&&h>>>8*j;j++){}if(j<15-a){j=15-a}e=k.clamp(e,8*(15-j));l=sjcl.mode.ccm._computeTag(c,b,e,m,d,j);f=sjcl.mode.ccm._ctrMode(c,f,e,l,d,j);return k.concat(f.data,f.tag)},decrypt:function(b,c,e,n,d){d=d||64;n=n||[];var j,g,l=sjcl.bitArray,a=l.bitLength(e)/8,h=l.bitLength(c),f=l.clamp(c,h-d),m=l.bitSlice(c,h-d),k;h=(h-d)/8;if(a<7){throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes")}for(j=2;j<4&&h>>>8*j;j++){}if(j<15-a){j=15-a}e=l.clamp(e,8*(15-j));f=sjcl.mode.ccm._ctrMode(b,f,e,m,d,j);k=sjcl.mode.ccm._computeTag(b,f.data,e,n,d,j);if(!l.equal(f.tag,k)){throw new sjcl.exception.corrupt("ccm: tag doesn't match")}return f.data},_computeTag:function(d,c,f,p,e,m){var b,l,n=0,g=24,j,h,a=[],o=sjcl.bitArray,k=o._xor4;e/=8;if(e%2||e<4||e>16){throw new sjcl.exception.invalid("ccm: invalid tag length")}if(p.length>0xffffffff||c.length>0xffffffff){throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data")}l=[o.partial(8,(p.length?1<<6:0)|(e-2)<<2|m-1)];l=o.concat(l,f);l[3]|=o.bitLength(c)/8;l=d.encrypt(l);if(p.length){j=o.bitLength(p)/8;if(j<=65279){a=[o.partial(16,j)]}else{if(j<=0xffffffff){a=o.concat([o.partial(16,65534)],[j])}}a=o.concat(a,p);for(h=0;h<a.length;h+=4){l=d.encrypt(k(l,a.slice(h,h+4).concat([0,0,0])))}}for(h=0;h<c.length;h+=4){l=d.encrypt(k(l,c.slice(h,h+4).concat([0,0,0])))}return o.clamp(l,e*8)},_ctrMode:function(d,j,g,q,f,n){var h,k,p=sjcl.bitArray,m=p._xor4,c,o,e=j.length,a=p.bitLength(j);c=p.concat([p.partial(8,n-1)],g).concat([0,0,0]).slice(0,4);q=p.bitSlice(m(q,d.encrypt(c)),0,f);if(!e){return{tag:q,data:[]}}for(k=0;k<e;k+=4){c[3]++;h=d.encrypt(c);j[k]^=h[0];j[k+1]^=h[1];j[k+2]^=h[2];j[k+3]^=h[3]}return{tag:q,data:p.clamp(j,a)}}};sjcl.misc.hmac=function(d,e){this._hash=e=e||sjcl.hash.sha256;var c=[[],[]],b,a=e.prototype.blockSize/32;this._baseHash=[new e(),new e()];if(d.length>a){d=e.hash(d)}for(b=0;b<a;b++){c[0][b]=d[b]^909522486;c[1][b]=d[b]^1549556828}this._baseHash[0].update(c[0]);this._baseHash[1].update(c[1]);this._resultHash=new e(this._baseHash[0])};sjcl.misc.hmac.prototype.encrypt=sjcl.misc.hmac.prototype.mac=function(a){if(!this._updated){this.update(a);return this.digest(a)}else{throw new sjcl.exception.invalid("encrypt on already updated hmac called!")}};sjcl.misc.hmac.prototype.reset=function(){this._resultHash=new this._hash(this._baseHash[0]);this._updated=false};sjcl.misc.hmac.prototype.update=function(a){this._updated=true;this._resultHash.update(a)};sjcl.misc.hmac.prototype.digest=function(){var b=this._resultHash.finalize(),a=new (this._hash)(this._baseHash[1]).update(b).finalize();this.reset();return a};

var Crypto = {
	keys: {},
	cipher: sjcl.cipher.aes,
	mode: sjcl.mode.ccm,
	hash: sjcl.hash.sha256,
	ivLength: 4
};

Crypto.getKey = function (fingerprint) {
	if (!(fingerprint in Crypto.keys)) throw new Error('unknown fingerprint', fingerprint);
	return Crypto.keys[fingerprint];
};

Crypto.hmac = function (secret, data) {
	var hmac = new sjcl.misc.hmac(secret, Crypto.hash);
	hmac.update(sjcl.codec.utf8String.toBits(data));
	return sjcl.codec.hex.fromBits(hmac.digest());
};

Crypto.encrypt = function (secret, data, adata) {
	var pt = sjcl.codec.utf8String.toBits(data);
	var iv = Array.prototype.slice.call(window.crypto.getRandomValues(new Uint32Array(Crypto.ivLength)));
	var ct = Crypto.mode.encrypt(new Crypto.cipher(secret), pt, iv, sjcl.codec.utf8String.toBits(adata));
	return sjcl.codec.base64.fromBits(iv.concat(ct));
};

Crypto.decrypt = function (secret, data, adata) {
	var ct = sjcl.codec.base64.toBits(data);
	var iv = ct.splice(0, Crypto.ivLength);
	var pt = Crypto.mode.decrypt(new Crypto.cipher(secret), ct, iv, sjcl.codec.utf8String.toBits(adata));
	return sjcl.codec.utf8String.fromBits(pt);
};

var Bloom = function (secret) {
	this.secret = secret;
	this.bits = {};
	this.count = 0;
};

Bloom.PREFIX_SHIFT = 25;
Bloom.M = 128;
Bloom.N = 20;
Bloom.K = 4;
Bloom.EXTRA_WORD_LENGTH = 8;

Bloom.prototype.hash = function (index, data) {
	var hmac = new sjcl.misc.hmac(this.secret, Crypto.hash);
	hmac.update([index]);
	hmac.update([0]);
	hmac.update(sjcl.codec.utf8String.toBits(data));
	return hmac.digest()[0] >>> Crypto.BLOOM_PREFIX_SHIFT;
};

Bloom.prototype.addInternal = function (item) {
	for (var j = 0; j < Bloom.K; j++) {
		this.bits[this.hash(j, b)] = true;
	}
	this.count++;
};

Bloom.prototype.addReal = function (data) {
	if (this.count >= Bloom.N) throw new Error('too many unique words');
	var item = sjcl.codec.utf8String.toBits(data);
	this.addInternal(item);
};

Bloom.prototype.addRandom = function () {
	var item = window.crypto.getRandomValues(new Uint32Array(Bloom.EXTRA_WORD_LENGTH));
	this.addInternal(item);
};

Bloom.prototype.pad = function () {
	while (this.count < Bloom.K) {
		this.addRandom();
	}
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
	LINK_PATTERN: /(?:@|#|\/r\/|\/u\/)\w+/g,
	LINK_TEST_PATTERN: /^(?:@|#|\/r\/|\/u\/)\w+$/, // same as above, but with ^...$
	WORD_PATTERN: /\w+/g, // todo: this could be better
	modes: {}
};

Tags.modes.none = function (secret, message) {
	// nothing!
};

Tags.modes.links = function (secret, message) {
	var tags = [];
	var seen = {};
	var match;
	while (match = Tags.LINK_PATTERN.exec(message)) {
		var tag = match[0];
		if (tag in seen) continue;
		tags.push(tag);
		seen[tag] = true;
	}
	return tags;
};

Tags.modes.words = function (secret, message) {
	var tags = [];
	var seen = {};
	var match;
	while (match = Tags.WORD_PATTERN.exec(message)) {
		// note: case sensitive
		var word = match[0];
		var name = ':' + word;
		if (name in seen) continue;
		var tag = Crypto.hmac(secret, word);
		tags.push(tag);
		seen[name] = true;
	}
	return tags.sort();
};

Tags.modes.wordsQuery = function (secret, message) {
	return Tags.modes.words(secret, message);
};
Tags.modes.wordsQuery.queryOnly = true;

Tags.modes.bloom = function (secret, message) {
	var match;
	var seen = {};
	var bloom = new Bloom(secret);
	var count = 0;
	while (match = Tags.WORD_PATTERN.exec(message)) {
		var word = match[0];
		var name = ':' + word;
		if (name in seen) continue;
		bloom.add(word);
		seen[name] = true;
	}
	var tags = [];
	for (var i = 0; i < Bloom.M; i++) {
		if (i in b) tags.push('b' + i);
	}
	return tags;
};

Tags.readLinks = function (impl, scanner, text, match) {
	var start = match.index + 12 + match[1].length + match[2].length;
	var end = start + match[3].length;
	var tags = [];
	while (start < end) {
		var comma = text.indexOf(',', start);
		if (comma === -1 || comma > end) comma = end;
		var tag = text.slice(start, comma);
		if (!Tags.LINK_TEST_PATTERN.test(tag)) continue;
		var range = impl.createRange();
		scanner.setStart(range, start);
		scanner.setEnd(range, comma);
		scanner.sink(range);
		tags.push([tag, range.cloneContents()]);
		start = comma + 1;
	}
	return tags;
};

Tags.insertLinks = function (impl, message, tags) {
	// might have matched CODE_PATTERN[3] but not any LINK_PATTERN
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
	CODE_PATTERN: /=\?zerokit-(\w*)\?([A-Za-z0-9+\/=]*)\?([^?\s]*)\?=/g
	// reflect changes in Tags.readLinks
};

Codec.encode = function (mode, fingerprint, message) {
	if (message === '') return '';
	var key = Crypto.getKey(fingerprint);
	if (mode.queryOnly) {
		return mode(message).join(' ');
	} else {
		var tags = mode(key.secret, message).join(',');
		var data = Crypto.encrypt(key.secret, message, tags);
		return '=?zerokit-' + fingerprint + '?' + data + '?' + tags + '?=';
	}
};

Codec.decode = function (fingerprint, data, tags) {
	var key = Crypto.getKey(fingerprint);
	return Crypto.decrypt(key.secret, data, tags);
};

var Rewriter = {
	FAST_FAIL_QUERY: '=?zerokit-',
	HIGHLIGHT_COLORS: [
		'rgba(51,153,153,0.125)',
		'rgba(51,102,153,0.125)',
		'rgba(102,102,153,0.125)',
		'rgba(173,73,119,0.125)',
		'rgba(209,174,74,0.125)',
		'rgba(153,102,51,0.125)',
		'rgba(102,102,102,0.125)'
	]
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
	// caveat: textContent includes comments and processing instructions
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
			var key = Crypto.getKey(match[1]);
			var messageText = Codec.decode(match[1], match[2], match[3]);
			var messageNode;
			if (match[3]) {
				var tags = Tags.readLinks(impl, scanner, text, match);
				messageNode = Tags.insertLinks(impl, messageText, tags);
			} else {
				messageNode = impl.createTextNode(messageText);
			}
			scanner.setEnd(range, match.index + match[0].length);
			scanner.sink(range, true);
			if (!Rewriter.checkRangeEndpoints(range)) throw new Error('aborting suspicious range');
			codes.push([range, key, messageNode]);
		} catch (e) {
			console.warn(e);
		}
	}
	return codes;
};

Rewriter.repaceCodes = function (impl, codes) {
	for (var i = 0; i < codes.length; i++) {
		var range = codes[i][0];
		var key = codes[i][1];
		var messageNode = codes[i][2];
		// caveat: this doesn't work in <title>
		var span = impl.createElement('span');
		span.zerokitReplaced = true;
		range.surroundContents(span);
		var shadowRoot = Compat.createShadowRoot(span);
		shadowRoot.applyAuthorStyles = true;
		shadowRoot.resetStyleInheritance = false;
		var highlight = impl.createElement('span');
		highlight.style.backgroundColor = Rewriter.HIGHLIGHT_COLORS[key.color];
		highlight.appendChild(messageNode);
		shadowRoot.appendChild(highlight);
		Compat.deleteShadowRootProp(span);
		// we'll need to prevent olderShadowRoot when it gets implemented
	}
};

Rewriter.rewriteMarkup = function (impl, node) {
	var codes = Rewriter.findCodes(impl, node);
	if (codes) Rewriter.repaceCodes(impl, codes);
};

Rewriter.replacer = function (code, fingerprint, tags, data) {
	try {
		return Codec.decode(fingerprint, tags, data);
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
	rules: null,
	adapters: {}
};

Widgets.AbstractAdapter = function (e) {
	this.node = e;
};

Widgets.Encrypted = function (e, o) {
	Widgets.AbstractAdapter.call(this, e);
	if ('mode' in o) {
		if (o.mode in Tags.modes) {
			this.mode = Tags.modes[o.mode];
		} else {
			console.error('mode %s is not defined (%s)', o.mode, e);
		}
	}
	if ('off' in o) {
		this.fingerprint = null;
	}
};
Widgets.Encrypted.prototype = Object.create(Widgets.AbstractAdapter.prototype);
Widgets.Encrypted.prototype.constructor = Widgets.Encrypted;

Widgets.Encrypted.prototype.mode = Tags.modes.links;
Widgets.Encrypted.prototype.fingerprint = null;

Widgets.Encrypted.prototype.encrypt = function (s) {
	if (this.fingerprint === null) return s;
	return Codec.encode(this.mode, this.fingerprint, s);
};

Widgets.Encrypted.prototype.decrypt = function (s) {
	return Rewriter.processString(s);
};

Widgets.Encrypted.prototype.refreshEncryption = function () {
	// abstract
};

Widgets.Encrypted.prototype.setFingerprint = function (fingerprint) {
	this.fingerprint = fingerprint;
	this.refreshEncryption();
};

Widgets.Encrypted.prototype.setMode = function (mode) {
	this.mode = mode;
	this.refreshEncryption();
};

Widgets.Delegated = function (e, o) {
	Widgets.Encrypted.call(this, e, o);
	var impl = this.node.ownerDocument;
	this.shadowContent = impl.createDocumentFragment();
	this.delegate = impl.createElement(this.delegateTagName);
	this.node.addEventListener('focus', this.onFocus.bind(this));
};
Widgets.Delegated.prototype = Object.create(Widgets.Encrypted.prototype);
Widgets.Delegated.prototype.constructor = Widgets.Delegated;

Widgets.Delegated.prototype.usePosition = function() {
	var style = this.node.ownerDocument.defaultView.getComputedStyle(this.node);
	switch (style.position) {
	case 'static':
		this.node.style.position = 'relative';
		break;
	}
};

Widgets.Delegated.prototype.activateDelegate = function() {
	var shadowRoot = Compat.createShadowRoot(this.node);
	Compat.deleteShadowRootProp(this.node);
	shadowRoot.applyAuthorStyles = false;
	shadowRoot.resetStyleInheritance = false;
	shadowRoot.appendChild(this.shadowContent);
	this.shadowContent = null;
	if (this.node.ownerDocument.activeElement === this.node) this.delegate.focus();
};

Widgets.Delegated.prototype.onFocus = function (e) {
	this.delegate.focus();
};

Widgets.KeyChanger = function (e, o) {
	Widgets.Delegated.call(this, e, o);
	if (!Widgets.KeyChanger.initialized) Widgets.KeyChanger.init();
	this.usePosition();

	var impl = this.node.ownerDocument;
	var style = impl.createElement('style');
	style.textContent = Widgets.KeyChanger.css;
	this.shadowContent.appendChild(style);
	this.wrapper = Widgets.KeyChanger.appendDiv(impl, this.shadowContent, 'wrapper');
		this.delegate.className = 'delegate';
		this.wrapper.appendChild(this.delegate);
		this.ui = Widgets.KeyChanger.appendDiv(impl, this.wrapper, 'ui');
			var modal = Widgets.KeyChanger.appendDiv(impl, this.ui, 'ui-modal');
			modal.addEventListener('click', this.clickModal.bind(this));
			var background = Widgets.KeyChanger.appendDiv(impl, this.ui, 'ui-background');
			var labelWrapper = Widgets.KeyChanger.appendDiv(impl, this.ui, 'label-wrapper');
				this.label = Widgets.KeyChanger.appendDiv(impl, labelWrapper, 'label');
			var ring = Widgets.KeyChanger.appendDiv(impl, this.ui, 'ring');
			var lock = Widgets.KeyChanger.appendDiv(impl, this.ui, 'lock');
			lock.addEventListener('click', this.clickLock.bind(this));

	this.keyCount = 0;
	this.keyElements = [];
	this.keyNameElements = [];
	for (var fingerprint in Crypto.keys) {
		var key = Crypto.keys[fingerprint];
		var keyWrapper = Widgets.KeyChanger.appendDiv(impl, ring, 'key-wrapper unlocked');
		var keyNameElement = Widgets.KeyChanger.appendDiv(impl, keyWrapper, 'key-name color-' + key.color);
		keyNameElement.textContent = key.name;
		this.keyNameElements.push(keyNameElement);
		var keyElement = Widgets.KeyChanger.appendDiv(impl, keyWrapper, 'key color-' + key.color);
		keyElement.style[Compat.transformProp] = 'rotate(150deg)';
		this.keyElements.push(keyElement);
		keyWrapper.addEventListener('mouseenter', this.enterKeyWrapper.bind(this, this.keyCount, fingerprint));
		keyWrapper.addEventListener('mouseleave', this.leaveKeyWrapper.bind(this, this.keyCount, fingerprint));
		keyWrapper.addEventListener('click', this.clickKeyWrapper.bind(this, this.keyCount, fingerprint));
		this.keyCount++;
	}

	this.keySpacing = Math.max(10, 50 - 5 * this.keyCount);
	this.extraSpacing = Math.max(0, 30 - this.keySpacing);
	var keyRange = (this.keyCount - 1) * this.keySpacing;
	this.keyOffsetStart = -0.5 * keyRange;
	this.keyNamesStart = 22 + this.keyOffsetStart;
	this.positionKeyNames();

	var unlock = Widgets.KeyChanger.appendDiv(impl, ring, 'key-name unlock');
	unlock.textContent = 'Unlock';
	unlock.addEventListener('click', this.clickUnlock.bind(this));

	this.keySelectionVisible = false;
	this.refreshState();
};
Widgets.KeyChanger.prototype = Object.create(Widgets.Delegated.prototype);
Widgets.KeyChanger.prototype.constructor = Widgets.KeyChanger;

Widgets.KeyChanger.initialized = false;
Widgets.KeyChanger.css = null;

Widgets.KeyChanger.appendDiv = function (impl, container, className) {
	var div = impl.createElement('div');
	div.className = className;
	container.appendChild(div);
	return div;
};

Widgets.KeyChanger.init = function (impl) {
	Widgets.KeyChanger.css =
		'.delegate{display:block;margin:0;border:medium none;padding:0;background:transparent;font:inherit;color:inherit;outline:1px solid transparent;outline-offset:0;}\r\n' +
		'.delegate:focus{outline-width:2px;}\r\n' +
		'.ui{position:absolute;bottom:0.625em;right:20px;}\r\n' +
		'.key-ui.ui{z-index:1;}\r\n' +
		'.ui-background{position:absolute;width:600px;height:600px;left:-300px;top:-300px;background-image:radial-gradient(closest-side,white 0%,rgba(255,255,255,0.3) 50%,rgba(255,255,255,0) 100%);transition:all ease-in-out 0.2s 0s;opacity:0;visibility:hidden;}\r\n' +
		'.key-ui .ui-background{opacity:1;visibility:visible;}\r\n' +
		'.ui-modal{position:fixed;top:0;left:0;bottom:0;right:0;background-color:white;transition:all ease-in-out 0.2s 0s;opacity:0;visibility:hidden;}\r\n' +
		'.key-ui .ui-modal{opacity:0.5;visibility:visible;}\r\n' +
		'.label-wrapper{position:absolute;top:12px;transition:all ease-in-out 0.2s 0s;opacity:0;visibility:hidden;}\r\n' +
		'.ui:hover .label-wrapper{opacity:1;visibility:visible;}\r\n' +
		'.ui.key-ui .label-wrapper{opacity:0;visibility:hidden;}\r\n' +
		'.label{position:relative;left:-50%;border:1px solid #cccccc;padding:3px;background-color:white;font:10px sans-serif;white-space:nowrap;}\r\n' +
		'.wrapper.unlocked .label{display:none;}\r\n' +
		'.ring{position:absolute;left:-34px;top:-34px;border:2px solid #999999;border-radius:64px;width:64px;height:64px;transition:all ease-in-out 0.2s 0s;' + Compat.transformOrigin + ':50% 50%;' + Compat.transform + ':scale(0,0);opacity:0;}\r\n' +
		'.key-ui .ring{' + Compat.transform + ':scale(1,1);opacity:1;}\r\n' +
		'.key{width:40px;height:25px;background-image:url(' + chrome.extension.getURL('Spritesheet-01.png') + ');}\r\n' +
		'.ring .key{position:absolute;left:55px;top:20px;transition:all ease-in-out 0.2s 0s;' + Compat.transformOrigin + ':-23px 50%;cursor:pointer;}\r\n' +
		'.key-name{position:absolute;padding:3px;font:500 10px sans-serif;white-space:nowrap;cursor:pointer;transition:all ease-in-out 0.2s 0s;opacity:0.8;}\r\n' +
		'.key-wrapper:hover .key-name,.key-name.unlock:hover{opacity:1;' + Compat.transform + ':scale(1.2,1.2);}\r\n' +
		'.key-name.unlock{top:75px;left:12px;color:dimgray;}\r\n' +
		'.lock{position:absolute;bottom:-20px;left:-20px;width:40px;height:40px;background:-160px -120px url(' + chrome.extension.getURL('Spritesheet-01.png') + ');cursor:pointer;}\r\n' +
		'.lock:hover,.key-ui .lock{opacity:1;}\r\n' +
		'\r\n' +
		'.key.color-1{background-position:0 -25px;}\r\n' +
		'.key.color-2{background-position:0 -50px;}\r\n' +
		'.key.color-3{background-position:0 -75px;}\r\n' +
		'.key.color-4{background-position:0 -100px;}\r\n' +
		'.key.color-5{background-position:0 -125px;}\r\n' +
		'.key.color-6{background-position:0 -150px;}\r\n' +
		'.wrapper.locked-color-0 .lock{background-position:-120px 0;}\r\n' +
		'.wrapper.locked-color-1 .lock{background-position:-120px -40px;}\r\n' +
		'.wrapper.locked-color-2 .lock{background-position:-120px -80px;}\r\n' +
		'.wrapper.locked-color-3 .lock{background-position:-120px -120px;}\r\n' +
		'.wrapper.locked-color-4 .lock{background-position:-160px 0;}\r\n' +
		'.wrapper.locked-color-5 .lock{background-position:-160px -40px;}\r\n' +
		'.wrapper.locked-color-6 .lock{background-position:-160px -80px;}\r\n' +
		'.wrapper.locked-color-0 .label,.key-name.color-0{color:#339999;}\r\n' +
		'.wrapper.locked-color-1 .label,.key-name.color-1{color:#336699;}\r\n' +
		'.wrapper.locked-color-2 .label,.key-name.color-2{color:#666699;}\r\n' +
		'.wrapper.locked-color-3 .label,.key-name.color-3{color:#ad4977;}\r\n' +
		'.wrapper.locked-color-4 .label,.key-name.color-4{color:#d1ae4a;}\r\n' +
		'.wrapper.locked-color-5 .label,.key-name.color-5{color:#996633;}\r\n' +
		'.wrapper.locked-color-6 .label,.key-name.color-6{color:#666666;}\r\n' +
		'.wrapper.locked-color-0 .delegate{outline-color:#339999;}\r\n' +
		'.wrapper.locked-color-1 .delegate{outline-color:#336699;}\r\n' +
		'.wrapper.locked-color-2 .delegate{outline-color:#666699;}\r\n' +
		'.wrapper.locked-color-3 .delegate{outline-color:#ad4977;}\r\n' +
		'.wrapper.locked-color-4 .delegate{outline-color:#d1ae4a;}\r\n' +
		'.wrapper.locked-color-5 .delegate{outline-color:#996633;}\r\n' +
		'.wrapper.locked-color-6 .delegate{outline-color:#666666;}\r\n' /* +
		'.wrapper.locked-color-0 .delegate:focus{box-shadow:inset 0 0 5px #339999;}\r\n' +
		'.wrapper.locked-color-1 .delegate:focus{box-shadow:inset 0 0 5px #336699;}\r\n' +
		'.wrapper.locked-color-2 .delegate:focus{box-shadow:inset 0 0 5px #666699;}\r\n' +
		'.wrapper.locked-color-3 .delegate:focus{box-shadow:inset 0 0 5px #ad4977;}\r\n' +
		'.wrapper.locked-color-4 .delegate:focus{box-shadow:inset 0 0 5px #d1ae4a;}\r\n' +
		'.wrapper.locked-color-5 .delegate:focus{box-shadow:inset 0 0 5px #996633;}\r\n' +
		'.wrapper.locked-color-6 .delegate:focus{box-shadow:inset 0 0 5px #666666;}\r\n' */;
};

Widgets.KeyChanger.prototype.refreshState = function () {
	if (this.fingerprint === null) {
		this.wrapper.className = 'wrapper unlocked';
		this.label.textContent = '';
	} else {
		var key = Crypto.keys[this.fingerprint];
		this.wrapper.className = 'wrapper locked-color-' + key.color;
		this.label.textContent = key.name + ': ' + key.passphrase;
	}
};

Widgets.KeyChanger.prototype.setFingerprint = function (fingerprint) {
	Widgets.Encrypted.prototype.setFingerprint.call(this, fingerprint);
	this.refreshState();
};

Widgets.KeyChanger.prototype.positionKeyNames = function () {
	for (var i = 0; i < this.keyCount; i++) {
		var top = this.keyNamesStart + this.keySpacing * i;
		var rotation = (this.keyOffsetStart + i * this.keySpacing) / 180 * Math.PI;
		var left = 40 * Math.cos(rotation) + 60;
		this.keyNameElements[i].style.top = top + 'px';
		this.keyNameElements[i].style.left = left + 'px';
	}
};

Widgets.KeyChanger.prototype.rotateKeys = function (option) {
	for (var i = 0; i < this.keyCount; i++) {
		var rotation;
		if (option === 'collapsed') {
			rotation = 150;
		} else {
			rotation = this.keyOffsetStart + this.keySpacing * i;
			if (option !== 'uniform') {
				if (i < option) rotation -= this.extraSpacing;
				else if (i > option) rotation += this.extraSpacing;
			}
		}
		this.keyElements[i].style[Compat.transformProp] = 'rotate(' + rotation + 'deg)';
	}
};

Widgets.KeyChanger.prototype.hideKeySelection = function () {
	this.ui.classList.remove('key-ui');
	this.rotateKeys('collapsed');
	this.keySelectionVisible = false;
};

Widgets.KeyChanger.prototype.showKeySelection = function () {
	this.ui.classList.add('key-ui');
	this.rotateKeys('uniform');
	this.keySelectionVisible = true;
};

Widgets.KeyChanger.prototype.clickModal = function (e) {
	this.hideKeySelection();
	e.stopPropagation();
	e.preventDefault();
};

Widgets.KeyChanger.prototype.clickLock = function (e) {
	if (this.keySelectionVisible)  this.hideKeySelection();
	else this.showKeySelection();
	e.stopPropagation();
	e.preventDefault();
};

Widgets.KeyChanger.prototype.enterKeyWrapper = function (i, fingerprint, e) {
	if (this.keySelectionVisible) this.rotateKeys(i);
};

Widgets.KeyChanger.prototype.leaveKeyWrapper = function (i, fingerprint, e) {
	if (this.keySelectionVisible) this.rotateKeys('uniform');
};

Widgets.KeyChanger.prototype.clickKeyWrapper = function (i, fingerprint, e) {
	this.setFingerprint(fingerprint);
	this.hideKeySelection();
	e.stopPropagation();
	e.preventDefault();
};

Widgets.KeyChanger.prototype.clickUnlock = function (e) {
	this.setFingerprint(null);
	this.hideKeySelection();
	e.stopPropagation();
	e.preventDefault();
};

Widgets.adapters.Form = function (e, o) {
	Widgets.AbstractAdapter.call(this, e);
	this.node.addEventListener('submit', this.onSubmit.bind(this));
	Content.shimMethod(this.node, 'submit', this.submit.bind(this));
	// TODO: also listen for 'reset'
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

Widgets.adapters.Input = function (e, o) {
	Widgets.KeyChanger.call(this, e, o);
	this.setValue = Content.shimProp(this.node, 'value', this.node.value, this.onValueSet.bind(this));
	this.node.zerokitInputEarly = this.onInputEarly.bind(this);

	this.delegate.cssText = 'width:100%;height:100%;';
	this.delegate.value = this.decrypt(this.node.value);
	this.delegate.placeholder = this.decrypt(this.node.placeholder);
	this.delegate.addEventListener('change', this.onChange.bind(this), true);
	this.delegate.addEventListener('keydown', this.onKeyDown.bind(this), true);

	this.activateDelegate();
};
Widgets.adapters.Input.prototype = Object.create(Widgets.KeyChanger.prototype);
Widgets.adapters.Input.prototype.constructor = Widgets.adapters.Input;

Widgets.adapters.Input.prototype.delegateTagName = 'input';

Widgets.adapters.Input.prototype.refreshEncryption = function () {
	var plain = this.delegate.value;
	var cipher = this.encrypt(plain);
	this.node.value = cipher;
	this.setValue(cipher);
	// TODO: this should probably dispatch an input event
};

Widgets.adapters.Input.prototype.onValueSet = function (v) {
	var cipher = v;
	var plain = this.decrypt(cipher);
	this.node.value = cipher;
	this.delegate.value = plain;
};

Widgets.adapters.Input.prototype.onInputEarly = function () {
	this.refreshEncryption();
};

Widgets.adapters.Input.prototype.onChange = function (e) {
	var event = new Event('change');
	this.node.dispatchEvent(event);
};

Widgets.adapters.Input.prototype.onKeyDown = function (e) {
	if (e.keyCode === 13) {
		if (!e.defaultPrevented && this.node.form) {
			var event = new Event('submit');
			this.node.form.dispatchEvent(event);
			// caveat: doesn't take into account form* attributes
			this.node.form.submit();
		}
	} else if (e.keyCode == 32 && e.ctrlKey) {
		if (this.fingerprint === null) {
			this.setFingerprint(Widgets.Encrypted.prototype.fingerprint);
		} else {
			this.setFingerprint(null);
		}
		e.preventDefault();
	}
};

Widgets.adapters.TextArea = function (e, o) {
	Widgets.Encrypted.call(this, e, o);
	this.publicValue = this.node.value;
	this.setValue = Content.shimProp(this.node, 'value', this.publicValue, this.onValueSet.bind(this));
	this.node.value = this.decrypt(this.node.value);
	this.node.zerokitDodge = this.dodge.bind(this);
	this.node.zerokitInputEarly = this.onInputEarly.bind(this);
	this.node.addEventListener('keydown', this.onKeyDown.bind(this), true);
};
Widgets.adapters.TextArea.prototype = Object.create(Widgets.Encrypted.prototype);
Widgets.adapters.TextArea.prototype.constructor = Widgets.adapters.TextArea;

Widgets.adapters.TextArea.prototype.refreshEncryption = function () {
	var plain = this.node.value;
	var cipher = this.encrypt(plain);
	this.publicValue = cipher;
	this.setValue(cipher);
	// TODO: this should probably dispatch an input event
};

Widgets.adapters.TextArea.prototype.onValueSet = function (v) {
	var cipher = v;
	var plain = this.decrypt(cipher);
	this.node.value = plain;
	this.publicValue = cipher;
};

Widgets.adapters.TextArea.prototype.onInputEarly = function () {
	this.refreshEncryption();
};

Widgets.adapters.TextArea.prototype.onKeyDown = function (e) {
	if (e.keyCode == 32 && e.ctrlKey) {
		if (this.fingerprint === null) {
			this.setFingerprint(Widgets.Encrypted.prototype.fingerprint);
		} else {
			this.setFingerprint(null);
		}
		e.preventDefault();
	}
};

Widgets.adapters.TextArea.prototype.dodge = function () {
	var privateValue = this.node.value;
	this.node.value = this.publicValue;
	return function () {
		this.node.value = privateValue;
	}.bind(this);
};

Widgets.adapters.ContentEditable = function (e, o) {
	Widgets.KeyChanger.call(this, e, o);
	this.node.zerokitUpdateContent = this.updateContent.bind(this);

	var impl = this.node.ownerDocument;
	// caveat: height:100% only works when the parent has explicit height
	this.delegate.style.cssText = 'position:absolute;top:0;left:0;bottom:0;right:0;width:auto;height:auto;';
	this.delegate.value = this.decrypt(Compat.getInnerText(this.node));
	this.delegate.addEventListener('input', this.onInput.bind(this), true);
	this.delegate.addEventListener('keyup', Widgets.adapters.ContentEditable.stopEvent);
	this.delegate.addEventListener('keydown', Widgets.adapters.ContentEditable.stopEvent);
	this.delegate.addEventListener('keypress', Widgets.adapters.ContentEditable.stopEvent);

	/*
	// set explicit height, which caveat: might be undesirable
	if (this.node === impl.body) {
		// if this is the <body>, maximize height
		var style = impl.defaultView.getComputedStyle(this.node);
		var margin = style.margin;
		this.node.style.margin = '0';
		this.delegate.style.boxSizing = 'border-box';
		this.delegate.style.padding = margin;
		impl.documentElement.style.height = '100%';
		this.node.style.boxSizing = 'border-box';
		this.node.style.height = '100%';
	} else {
		var offsetHeight = this.node.offsetHeight;
		if (offsetHeight > 0) {
			// lock in current height
			this.node.style.boxSizing = 'border-box';
			this.node.style.height = offsetHeight + 'px';
		}
	}
	*/

	// note: this empties out innerText
	this.activateDelegate();
};
Widgets.adapters.ContentEditable.prototype = Object.create(Widgets.KeyChanger.prototype);
Widgets.adapters.ContentEditable.prototype.constructor = Widgets.adapters.ContentEditable;

Widgets.adapters.ContentEditable.stopEvent = function (e) {
	e.stopPropagation();
};

Widgets.adapters.ContentEditable.prototype.delegateTagName = 'textarea';

Widgets.adapters.ContentEditable.prototype.refreshEncryption = function () {
	var plain = this.delegate.value;
	var cipher = this.encrypt(plain);
	this.node.textContent = cipher;
	// TODO: this should probably dispatch an input event
};

Widgets.adapters.ContentEditable.prototype.onInput = function (e) {
	this.refreshEncryption();
};

Widgets.adapters.ContentEditable.prototype.updateContent = function () {
	// caveat: this is stuck with textContent, since innerText uses the composed tree
	var cipher = this.node.textContent;
	var plain = this.decrypt(cipher);
	this.delegate.value = plain;
};

Widgets.adapters.IFrame = function (e, o) {
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

Widgets.createAdapter = function (node, rule) {
	var tag = node.tagName.toLowerCase();
	if (tag === 'form') {
		return new Widgets.adapters.Form(node, rule);
	} else if (tag === 'input') {
		if (node.type === 'text') {
			// TODO: more heuristics
			return new Widgets.adapters.Input(node, rule);
		}
	} else if (tag === 'textarea') {
		return new Widgets.adapters.TextArea(node, rule);
	} else if (tag === 'iframe') {
		return new Widgets.adapters.IFrame(node, rule);
	} else {
		if (node.contentEditable === 'true') {
			return new Widgets.adapters.ContentEditable(node, rule);
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
	if ('zerokitSeenWidget' in node) return;
	var rule = Widgets.findRule(node);
	if (!('noShim' in rule)) Widgets.createAdapter(node, rule);
	node.zerokitSeenWidget = true;
};

Widgets.findRule = function (node) {
	for (var i = 0; i < Widgets.rules.length; i++) {
		var rule = Widgets.rules[i];
		if (Compat.matches(node, rule.selector)) return rule;
	}
	return {};
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
	name: null
};

Startup.init = function () {
	Startup.name = 'origin-' + window.location.origin;
	chrome.storage.sync.get(Startup.name, Startup.onGet);
};

Startup.onGet = function (items) {
	if (!(Startup.name in items)) return;
	var site = items[Startup.name];
	Crypto.keys = site.keys;
	Widgets.Encrypted.prototype.fingerprint = site.defaultFingerprint;
	Widgets.rules = Startup.filterRules(site.rules);

	Content.init();
	Widgets.init(window);
	Observer.init(document);
};

Startup.filterRules = function (rules) {
	var applicable = [];
	var url = window.location.href;
	for (var i = 0; i < rules.length; i++) {
		var rule = rules[i];
		if (rule.urlPattern.test(url)) applicable.push(rule);
	}
	return applicable;
};

Startup.init();
